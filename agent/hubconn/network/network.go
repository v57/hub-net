// Package network implements Hub Network share publication for Go services.
//
// A service declares local TCP/UDP shares; the publisher obtains a signed
// attestation from the local hub-net agent (proving the service owns the local
// target), submits the attested shares to Hub via `network/shares/replace`, and
// stores the returned overlay publications. On Hub reconnect the SDK republishes
// the full declared set. Wire format and IPC flow mirror the Bun hub-service
// network module.
package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	protocol "github.com/v57/hub-net-node/models"
)

// WireVersion is the Hub Network protocol wire version.
const WireVersion = protocol.WireVersion

// DefaultAgentSocket is the macOS hub-net agent Unix socket path.
const DefaultAgentSocket = "/var/run/hub-net/agent.sock"

// DefaultAgentTimeout is the local-agent request timeout.
const DefaultAgentTimeout = 5 * time.Second

// Protocol is a published network share transport protocol.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// PolicyMode controls which network profiles may reach a share.
type PolicyMode string

const (
	PolicyHub      PolicyMode = "hub"
	PolicyGroup    PolicyMode = "group"
	PolicyKeys     PolicyMode = "keys"
	PolicyPrivate  PolicyMode = "private"
	PolicyDisabled PolicyMode = "disabled"
)

// Policy declares the access policy for a share.
type Policy struct {
	Mode  PolicyMode
	Group string
	Keys  []string
}

// Share is a locally published TCP/UDP target.
type Share struct {
	Name     string
	Protocol Protocol
	Host     string
	Port     uint16
	Policy   *Policy
}

// Publication is the overlay result returned by Hub after a successful share
// replacement.
type Publication = protocol.NetworkSharePublication

// Attestation is the local-agent signed proof that the service owns the share
// target.
type Attestation = protocol.AgentAttestation

// ErrShareDeviceMismatch is the Hub's refusal of a share fronted by an agent
// on another device than the service's certificate names: a share's address
// is its service's device, so only that device's agent may front it
// (Docs/Devices/protocol.md section 10).
var ErrShareDeviceMismatch = errors.New("share_device_mismatch")

// LocalAgentErrorCode classifies local-agent IPC failures.
type LocalAgentErrorCode string

const (
	AgentUnavailable     LocalAgentErrorCode = "agent-unavailable"
	AgentTimeout         LocalAgentErrorCode = "agent-timeout"
	AgentRejected        LocalAgentErrorCode = "agent-rejected"
	InvalidAgentResponse LocalAgentErrorCode = "invalid-agent-response"
	AttestationMismatch  LocalAgentErrorCode = "attestation-mismatch"
	AttestationExpired   LocalAgentErrorCode = "attestation-expired"
)

// LocalAgentError is returned for local-agent IPC failures.
type LocalAgentError struct {
	Code   LocalAgentErrorCode
	Status int
	Msg    string
}

func (e *LocalAgentError) Error() string { return e.Msg }

// Signer signs a local-agent challenge nonce with the service identity.
type Signer interface {
	SignChallenge(nonce string) (string, error)
}

// SignerFunc adapts a function to Signer.
type SignerFunc func(nonce string) (string, error)

// SignChallenge calls the underlying function.
func (f SignerFunc) SignChallenge(nonce string) (string, error) { return f(nonce) }

// Sender sends a request to Hub. Mirrors the channelgo Sender.Send shape.
type Sender interface {
	Send(path string, body any, contextValue ...any) (any, error)
}

// AttestationProvider returns a signed attestation for a share, optionally
// bypassing the default local-agent IPC flow (useful for tests or custom
// agents).
type AttestationProvider func(share Share, serviceKey string, signer Signer) (*Attestation, error)

// Options configures a Publisher.
type Options struct {
	// AgentSocket is the hub-net agent Unix socket path. Defaults to
	// DefaultAgentSocket.
	AgentSocket string
	// AgentTimeout is the local-agent request timeout. Defaults to
	// DefaultAgentTimeout.
	AgentTimeout time.Duration
	// AttestationProvider overrides the default local-agent attestation flow.
	AttestationProvider AttestationProvider
}

// Publisher manages declared network shares, local-agent attestation, and Hub
// share replacement.
type Publisher struct {
	mu                  sync.Mutex
	shares              map[string]Share
	publicationsByShare map[string]Publication
	provider            AttestationProvider
	agentSocket         string
	agentTimeout        time.Duration
}

// New constructs a Publisher.
func New(options Options) *Publisher {
	socket := options.AgentSocket
	if socket == "" {
		socket = DefaultAgentSocket
	}
	timeout := options.AgentTimeout
	if timeout == 0 {
		timeout = DefaultAgentTimeout
	}
	return &Publisher{
		shares:              make(map[string]Share),
		publicationsByShare: make(map[string]Publication),
		provider:            options.AttestationProvider,
		agentSocket:         socket,
		agentTimeout:        timeout,
	}
}

// Declare records a share so it is published atomically on the next
// synchronize call (initial connect or reconnect).
func (p *Publisher) Declare(share Share) {
	p.mu.Lock()
	p.shares[share.Name] = share
	p.mu.Unlock()
}

// Declared returns the declared shares sorted by name.
func (p *Publisher) Declared() []Share {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Share, 0, len(p.shares))
	for _, share := range p.shares {
		out = append(out, share)
	}
	sortShares(out)
	return out
}

// DeclaredShare returns a declared share by name.
func (p *Publisher) DeclaredShare(name string) (Share, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	share, ok := p.shares[name]
	return share, ok
}

// HasShares reports whether any shares are declared.
func (p *Publisher) HasShares() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.shares) > 0
}

// Publications returns the latest overlay publications.
func (p *Publisher) Publications() []Publication {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Publication, 0, len(p.publicationsByShare))
	for _, publication := range p.publicationsByShare {
		out = append(out, publication)
	}
	return out
}

// Publication returns the overlay publication for a share name.
func (p *Publisher) Publication(name string) (Publication, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pub, ok := p.publicationsByShare[name]
	return pub, ok
}

// Publish records the share and synchronizes with Hub, returning the new
// overlay publications. On failure the previously declared share is restored.
func (p *Publisher) Publish(ctx context.Context, share Share, serviceKey string, signer Signer, sender Sender) ([]Publication, error) {
	p.mu.Lock()
	previous, existed := p.shares[share.Name]
	p.shares[share.Name] = share
	p.mu.Unlock()
	publications, err := p.synchronize(ctx, serviceKey, signer, sender)
	if err != nil {
		p.mu.Lock()
		if existed {
			p.shares[share.Name] = previous
		} else {
			delete(p.shares, share.Name)
		}
		p.mu.Unlock()
		return nil, err
	}
	return publications, nil
}

// Remove deletes a declared share and synchronizes with Hub. On failure the
// share is restored.
func (p *Publisher) Remove(ctx context.Context, name, serviceKey string, signer Signer, sender Sender) ([]Publication, error) {
	p.mu.Lock()
	removed, existed := p.shares[name]
	if !existed {
		p.mu.Unlock()
		return nil, fmt.Errorf("network: share %q not found", name)
	}
	delete(p.shares, name)
	p.mu.Unlock()
	publications, err := p.synchronize(ctx, serviceKey, signer, sender)
	if err != nil {
		p.mu.Lock()
		p.shares[name] = removed
		p.mu.Unlock()
		return nil, err
	}
	return publications, nil
}

// Republish re-synchronizes all declared shares with Hub. Called on reconnect.
func (p *Publisher) Republish(ctx context.Context, serviceKey string, signer Signer, sender Sender) ([]Publication, error) {
	return p.synchronize(ctx, serviceKey, signer, sender)
}

// BuildReplacePayloadForTest builds the network/shares/replace payload for the
// given shares without contacting Hub. Exposed for cross-language conformance
// tests; not intended for production callers.
func (p *Publisher) BuildReplacePayloadForTest(shares []Share, provider AttestationProvider, serviceKey string) (protocol.SharesReplacePayload, error) {
	wireShares := make([]protocol.NetworkShare, 0, len(shares))
	for _, share := range shares {
		var attestation *Attestation
		var err error
		if provider != nil {
			attestation, err = provider(share, serviceKey, nil)
		}
		if err != nil {
			return protocol.SharesReplacePayload{}, err
		}
		if attestation == nil {
			attestation = &Attestation{Version: WireVersion}
		}
		wireShares = append(wireShares, toWireShare(share, attestation))
	}
	return protocol.SharesReplacePayload{Shares: wireShares}, nil
}

// synchronize obtains attestations for each declared share, sends
// network/shares/replace to Hub, and stores the returned publications.
func (p *Publisher) synchronize(ctx context.Context, serviceKey string, signer Signer, sender Sender) ([]Publication, error) {
	shares := p.Declared()
	wireShares := make([]protocol.NetworkShare, 0, len(shares))
	for _, share := range shares {
		attestation, err := p.attest(ctx, share, serviceKey, signer)
		if err != nil {
			return nil, err
		}
		if err := validateAttestation(attestation, share, serviceKey); err != nil {
			return nil, err
		}
		wireShares = append(wireShares, toWireShare(share, attestation))
	}

	response, err := sender.Send("network/shares/replace", protocol.SharesReplacePayload{Shares: wireShares})
	if err != nil {
		if strings.Contains(err.Error(), "share_device_mismatch") {
			return nil, fmt.Errorf("network: shares/replace: %w: %v", ErrShareDeviceMismatch, err)
		}
		return nil, fmt.Errorf("network: shares/replace: %w", err)
	}
	publications, err := decodePublications(response)
	if err != nil {
		return nil, err
	}
	if len(publications) != len(shares) {
		return nil, fmt.Errorf("network: hub returned %d publications for %d shares", len(publications), len(shares))
	}

	p.mu.Lock()
	clear(p.publicationsByShare)
	for index, share := range shares {
		p.publicationsByShare[share.Name] = publications[index]
	}
	p.mu.Unlock()
	return publications, nil
}

// attest obtains a signed attestation, using the custom provider when set or
// the default local-agent IPC flow otherwise.
func (p *Publisher) attest(ctx context.Context, share Share, serviceKey string, signer Signer) (*Attestation, error) {
	if p.provider != nil {
		return p.provider(share, serviceKey, signer)
	}
	return p.requestAttestation(ctx, share, serviceKey, signer)
}

// requestAttestation performs the local-agent challenge/attest IPC flow over
// the configured Unix socket.
func (p *Publisher) requestAttestation(ctx context.Context, share Share, serviceKey string, signer Signer) (*Attestation, error) {
	requestBody := challengeRequest{
		ServiceKey: serviceKey,
		ShareName:  share.Name,
		Protocol:   string(share.Protocol),
		Target:     protocol.LocalTarget{Host: share.Host, Port: share.Port},
	}

	challenge, err := p.agentPost(ctx, "/challenge", requestBody)
	if err != nil {
		return nil, err
	}
	nonce, ok := challenge["nonce"].(string)
	if !ok || nonce == "" {
		return nil, &LocalAgentError{Code: InvalidAgentResponse, Msg: "Hub Network agent returned an invalid challenge"}
	}
	signature, err := signer.SignChallenge(nonce)
	if err != nil {
		return nil, err
	}
	attestRequest := map[string]any{
		"serviceKey": serviceKey,
		"shareName":  share.Name,
		"protocol":   string(share.Protocol),
		"target":     requestBody.Target,
		"signature":  signature,
	}
	attestResponse, err := p.agentPost(ctx, "/attest", attestRequest)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(attestResponse)
	if err != nil {
		return nil, &LocalAgentError{Code: InvalidAgentResponse, Msg: "Hub Network agent returned invalid attestation", Status: 0}
	}
	var attestation Attestation
	if err := json.Unmarshal(encoded, &attestation); err != nil {
		return nil, &LocalAgentError{Code: InvalidAgentResponse, Msg: "Hub Network agent returned invalid attestation"}
	}
	return &attestation, nil
}

// agentPost sends a JSON POST to the local agent Unix socket and returns the
// decoded response body.
func (p *Publisher) agentPost(ctx context.Context, path string, body any) (map[string]any, error) {
	timeout := p.agentTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", p.agentSocket)
		},
	}
	client := &http.Client{Transport: transport}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, &LocalAgentError{Code: InvalidAgentResponse, Msg: "Hub Network agent request encoding failed"}
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, "http://localhost"+path, byteReader(encoded))
	if err != nil {
		return nil, &LocalAgentError{Code: AgentUnavailable, Msg: fmt.Sprintf("Hub Network agent is unavailable at %s", p.agentSocket)}
	}
	request.Header.Set("content-type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		if errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
			return nil, &LocalAgentError{Code: AgentTimeout, Msg: fmt.Sprintf("Hub Network agent timed out after %s", p.agentTimeout)}
		}
		return nil, &LocalAgentError{Code: AgentUnavailable, Msg: fmt.Sprintf("Hub Network agent is unavailable at %s", p.agentSocket)}
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail := string(payload)
		return nil, &LocalAgentError{
			Code:   AgentRejected,
			Status: response.StatusCode,
			Msg:    fmt.Sprintf("Hub Network agent rejected (%d)%s", response.StatusCode, optionalDetail(detail)),
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, &LocalAgentError{Code: InvalidAgentResponse, Msg: "Hub Network agent returned invalid JSON", Status: response.StatusCode}
	}
	return decoded, nil
}

// validateAttestation mirrors the Bun validateAttestation checks.
func validateAttestation(attestation *Attestation, share Share, serviceKey string) error {
	if attestation == nil {
		return &LocalAgentError{Code: AttestationMismatch, Msg: "Local-agent attestation does not match the share"}
	}
	if attestation.Version != WireVersion ||
		attestation.ServiceKey != serviceKey ||
		attestation.ShareName != share.Name ||
		attestation.Protocol != string(share.Protocol) ||
		attestation.Target.Host != share.Host ||
		attestation.Target.Port != share.Port {
		return &LocalAgentError{Code: AttestationMismatch, Msg: "Local-agent attestation does not match the share"}
	}
	issuedAt, err := time.Parse(time.RFC3339, attestation.IssuedAt)
	if err != nil {
		return &LocalAgentError{Code: AttestationExpired, Msg: "Local-agent attestation is expired"}
	}
	expiresAt, err := time.Parse(time.RFC3339, attestation.ExpiresAt)
	if err != nil {
		return &LocalAgentError{Code: AttestationExpired, Msg: "Local-agent attestation is expired"}
	}
	if expiresAt.IsZero() || !expiresAt.After(time.Now()) || issuedAt.IsZero() {
		return &LocalAgentError{Code: AttestationExpired, Msg: "Local-agent attestation is expired"}
	}
	return nil
}

// toWireShare builds the versioned wire share submitted to Hub.
func toWireShare(share Share, attestation *Attestation) protocol.NetworkShare {
	return protocol.NetworkShare{
		Version:     WireVersion,
		Name:        share.Name,
		Protocol:    string(share.Protocol),
		Target:      protocol.LocalTarget{Host: share.Host, Port: share.Port},
		Policy:      toWirePolicy(share.Policy),
		Attestation: *attestation,
	}
}

// toWirePolicy converts the local Policy to the protocol NetworkPolicy.
func toWirePolicy(policy *Policy) *protocol.NetworkPolicy {
	if policy == nil {
		return &protocol.NetworkPolicy{Mode: string(PolicyPrivate)}
	}
	return &protocol.NetworkPolicy{
		Mode:  string(policy.Mode),
		Group: policy.Group,
		Keys:  policy.Keys,
	}
}

// decodePublications decodes the network/shares/replace response into typed
// publications. The response arrives as decoded JSON (map[string]any).
func decodePublications(response any) ([]Publication, error) {
	if response == nil {
		return nil, errors.New("network: empty shares/replace response")
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("network: decode publications: %w", err)
	}
	var wrapper struct {
		Shares []Publication `json:"shares"`
	}
	if err := json.Unmarshal(encoded, &wrapper); err != nil {
		return nil, fmt.Errorf("network: decode publications: %w", err)
	}
	return wrapper.Shares, nil
}
