// registrar.go sends the hub/net/bind message on every Hub
// (re)connect, updating the profile lifecycle as Hub responds.
//
// Hub requires the agent to register its profile after authentication so it
// can bind the WireGuard key, allocate overlay addresses, and list the agent
// for callers. Registration is idempotent per connection: hub-pro resets
// agent state on disconnect (HN-101) and re-issues overlay addresses on the
// next register call, so the agent re-registers on every reconnect.
package profile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/v57/channel-go/channelgo"
	protocol "github.com/v57/hub-net-node/models"
)

// DefaultRegistrationTimeout bounds the synchronous register call. The Hub
// responds quickly; a long block indicates Hub trouble rather than a slow
// operation.
const DefaultRegistrationTimeout = 10 * time.Second

// Registrar sends hub/net/bind and updates the Profile lifecycle.
type Registrar struct {
	profile     *Profile
	key         string
	timeout     time.Duration
	platform    string
	name        string
	bindingKind protocol.LocalAgentBindingKind
}

// RegistrarOptions configures the Registrar.
type RegistrarOptions struct {
	Profile  *Profile
	Key      string
	Timeout  time.Duration
	Name     string
	Platform string
	// BindingKind defaults to machine (the hub-pro host's own agent).
	BindingKind protocol.LocalAgentBindingKind
}

// NewRegistrar constructs a Registrar. Key is the authenticated Hub
// service key of the agent's Hub identity; the Hub enforces it matches the
// connection.
func NewRegistrar(options RegistrarOptions) (*Registrar, error) {
	if options.Profile == nil {
		return nil, errors.New("profile: registrar requires Profile")
	}
	if options.Key == "" {
		return nil, errors.New("profile: registrar requires Key")
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = DefaultRegistrationTimeout
	}
	platform := options.Platform
	if platform == "" {
		platform = runtime.GOOS
	}
	bindingKind := options.BindingKind
	if bindingKind == "" {
		bindingKind = protocol.LocalAgentBindingMachine
	}
	return &Registrar{
		bindingKind: bindingKind,
		profile:     options.Profile,
		key:         options.Key,
		timeout:     timeout,
		platform:    platform,
		name:        options.Name,
	}, nil
}

// RegisterBody returns the wire body sent to hub/net/bind. Exported
// so tests can assert the shape without spinning up a Channel.
func (r *Registrar) RegisterBody() (protocol.AgentBindRequest, error) {
	snap := r.profile.Snapshot()
	wgKey, err := encodeWireGuardPublic(snap.WireGuardPubKey)
	if err != nil {
		return protocol.AgentBindRequest{}, err
	}
	return protocol.AgentBindRequest{
		AgentProfileRegistration: protocol.AgentProfileRegistration{
			Version: protocol.WireVersion, WireGuardKey: wgKey, Name: r.name,
			Platform: r.platform, OverlayAddresses: []string{},
			ConnectedAt: time.Now().UTC().Format(time.RFC3339Nano),
		},
		BindingKind: r.bindingKind,
	}, nil
}

// Register sends hub/net/bind through sender and records the Hub
// response. The Hub allocates overlay addresses and binds the WireGuard key
// to the profile. On success the profile moves to Registered with the Hub
// issued overlay address.
func (r *Registrar) Register(ctx context.Context, sender *channelgo.Sender) error {
	if sender == nil {
		return errors.New("profile: register requires a connected sender")
	}
	body, err := r.RegisterBody()
	if err != nil {
		return err
	}
	r.profile.BeginRegistration()
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	// channel-go decodes JSON responses into generic any (map[string]any) on
	// the client side; we round-trip through JSON to land in registerResponse
	// so both the in-process inline transport and the WebSocket transport
	// produce the same typed value.
	raw, err := sender.Send("hub/net/bind", body)
	if err != nil {
		r.profile.SetState(StateRegistering)
		return fmt.Errorf("profile: hub/net/bind: %w", err)
	}
	response, err := decodeRegisterResponse(raw)
	if err != nil {
		r.profile.SetState(StateRegistering)
		return fmt.Errorf("profile: hub/net/bind: %w", err)
	}
	registered := response.extract()
	if registered.Key != r.key {
		r.profile.SetState(StateUnregistered)
		return fmt.Errorf("profile: hub returned mismatched profile registration")
	}
	// Persist Hub trust returned by binding so compact invitations can identify
	// their signer without carrying the Hub public key.
	r.profile.ConfirmRegistration(
		firstOrEmpty(registered.OverlayAddresses),
		registered.HubNetworkID,
		0,
		registered.HubKey,
	)
	return nil
}

// OnConnect returns a channelgo-compatible callback that performs Register
// with the configured timeout. It is the hook installed as
// hubconn.Options.OnConnect so the agent re-registers on every reconnect.
func (r *Registrar) OnConnect() func(sender *channelgo.Sender) {
	return func(sender *channelgo.Sender) {
		// Errors are surfaced through profile state; the SDK never aborts the
		// connection from OnConnect.
		_ = r.Register(context.Background(), sender)
	}
}

// encodeWireGuardPublic base64-encodes the 32-byte Curve25519 public key for
// the wire AgentProfile.wireGuardKey field.
func encodeWireGuardPublic(raw []byte) (string, error) {
	const wireGuardKeyLength = 32
	if len(raw) != wireGuardKeyLength {
		return "", fmt.Errorf("profile: wireguard public key length %d", len(raw))
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// decodeRegisterResponse normalizes the channel-go response into the typed
// registerResponse. The WebSocket transport delivers decoded JSON as
// map[string]any; the in-process inline transport may deliver the value
// directly. We accept both.
func decodeRegisterResponse(raw any) (registerResponse, error) {
	if raw == nil {
		return registerResponse{Success: true}, nil
	}
	if typed, ok := raw.(registerResponse); ok {
		return typed, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return registerResponse{}, fmt.Errorf("encode response: %w", err)
	}
	var response registerResponse
	if err := json.Unmarshal(encoded, &response); err != nil {
		return registerResponse{}, fmt.Errorf("decode response: %w", err)
	}
	return response, nil
}

// registerResponse mirrors the Hub hub/net/bind reply. The Hub
// returns the full registered profile and Hub signing identity.
type registerResponse struct {
	Success      bool                  `json:"success"`
	Profile      protocol.AgentProfile `json:"profile,omitempty"`
	HubKey       string                `json:"hubKey,omitempty"`
	HubNetworkID string                `json:"hubNetworkId,omitempty"`
}

// extract pulls the registered profile from the response. When the Hub omits
// the profile we leave overlay addresses empty; they arrive via the agents
// list stream in later tasks, but the lifecycle still moves to Registered.
func (r registerResponse) extract() extractedProfile {
	if r.Profile.Key != "" {
		return extractedProfile{
			Key:              r.Profile.Key,
			OverlayAddresses: r.Profile.OverlayAddresses,
			HubKey:           r.HubKey,
			HubNetworkID:     r.HubNetworkID,
		}
	}
	return extractedProfile{HubKey: r.HubKey, HubNetworkID: r.HubNetworkID}
}

type extractedProfile struct {
	Key              string
	OverlayAddresses []string
	HubKey           string
	HubNetworkID     string
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
