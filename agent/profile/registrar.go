// registrar.go sends the network/agent/register message on every Hub
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
	"github.com/v57/hub-service-go/protocol"
)

// DefaultRegistrationTimeout bounds the synchronous register call. The Hub
// responds quickly; a long block indicates Hub trouble rather than a slow
// operation.
const DefaultRegistrationTimeout = 10 * time.Second

// Registrar sends network/agent/register and updates the Profile lifecycle.
type Registrar struct {
	profile   *Profile
	agentKey  string
	timeout   time.Duration
	platform  string
	name      string
}

// RegistrarOptions configures the Registrar.
type RegistrarOptions struct {
	Profile  *Profile
	AgentKey string
	Timeout  time.Duration
	Name     string
	Platform string
}

// NewRegistrar constructs a Registrar. AgentKey is the authenticated Hub
// service key of the agent's Hub identity; the Hub enforces it matches the
// connection.
func NewRegistrar(options RegistrarOptions) (*Registrar, error) {
	if options.Profile == nil {
		return nil, errors.New("profile: registrar requires Profile")
	}
	if options.AgentKey == "" {
		return nil, errors.New("profile: registrar requires AgentKey")
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = DefaultRegistrationTimeout
	}
	platform := options.Platform
	if platform == "" {
		platform = runtime.GOOS
	}
	return &Registrar{
		profile:  options.Profile,
		agentKey: options.AgentKey,
		timeout:  timeout,
		platform: platform,
		name:     options.Name,
	}, nil
}

// RegisterBody returns the wire body sent to network/agent/register. Exported
// so tests can assert the shape without spinning up a Channel.
func (r *Registrar) RegisterBody() (protocol.AgentProfile, error) {
	snap := r.profile.Snapshot()
	wgKey, err := encodeWireGuardPublic(snap.WireGuardPubKey)
	if err != nil {
		return protocol.AgentProfile{}, err
	}
	return protocol.AgentProfile{
		Version:          protocol.WireVersion,
		ProfileKey:       snap.ProfileKey,
		AgentKey:         r.agentKey,
		WireGuardKey:     wgKey,
		Name:             r.name,
		Platform:         r.platform,
		OverlayAddresses: []string{},
		ConnectedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

// Register sends network/agent/register through sender and records the Hub
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
	raw, err := sender.Send("network/agent/register", body)
	if err != nil {
		r.profile.SetState(StateRegistering)
		return fmt.Errorf("profile: network/agent/register: %w", err)
	}
	response, err := decodeRegisterResponse(raw)
	if err != nil {
		r.profile.SetState(StateRegistering)
		return fmt.Errorf("profile: network/agent/register: %w", err)
	}
	registered := response.extract()
	if registered.ProfileKey != body.ProfileKey || registered.AgentKey != body.AgentKey {
		r.profile.SetState(StateUnregistered)
		return fmt.Errorf("profile: hub returned mismatched profile registration")
	}
	// hub-pro returns {success: true} today and does not echo hubKey/hubNetworkId
	// back through this path. The Hub MAY include them so the agent can build a
	// grant.LocalBinding without waiting for the first grant; otherwise the
	// fields stay empty and are seeded from the first signature-verified grant.
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
// hubservice.Options.OnConnect so the agent re-registers on every reconnect.
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

// registerResponse mirrors the Hub network/agent/register reply. The Hub
// currently returns `{success: true}`; we also accept the full registered
// profile so future Hub versions can echo allocated addresses back without a
// follow-up stream read. HubKey/HubNetworkID are optional echoes of the trusted
// Hub signing identity (see Profile.ConfirmRegistration).
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
	if r.Profile.ProfileKey != "" {
		return extractedProfile{
			ProfileKey:       r.Profile.ProfileKey,
			AgentKey:         r.Profile.AgentKey,
			OverlayAddresses: r.Profile.OverlayAddresses,
			HubKey:           r.HubKey,
			HubNetworkID:     r.HubNetworkID,
		}
	}
	return extractedProfile{HubKey: r.HubKey, HubNetworkID: r.HubNetworkID}
}

type extractedProfile struct {
	ProfileKey       string
	AgentKey         string
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
