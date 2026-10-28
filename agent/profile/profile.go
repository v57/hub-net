// Package profile manages the hub-net agent network profile.
//
// The network profile is the access principal for overlay connections (design
// decision 3). It is distinct from the Hub RPC service identity: the profile
// is what `hub-server` authorizes in connection grants, while the service
// identity authenticates the agent's Hub RPC connection. HN-301 wires profile
// registration, identity persistence, WireGuard key lifecycle, and Hub
// reconnect; this scaffold defines the state and a small lifecycle API used
// by the agent.
package profile

import (
	"errors"
	"sync"
	"time"

	"github.com/v57/hub-net-node/identity"
)

// State describes where the profile sits in its lifecycle.
type State string

const (
	StateUnregistered State = "unregistered"
	StateRegistering  State = "registering"
	StateRegistered   State = "registered"
	StateRevoked      State = "revoked"
)

// Profile is the in-memory agent network profile. WireGuard key and identity
// material are held by keychain storage and referenced here by public keys.
type Profile struct {
	mu              sync.RWMutex
	state           State
	key             string // base64 SPKI of the Hub profile identity
	wireGuardPubKey []byte // raw 32-byte Curve25519 public key
	registeredAt    time.Time
	generation      uint64
	overlayAddress  string
	overlayIPv6     string
	hubNetworkID    string
	hubKey          string // base64 SPKI of the trusted Hub signing key
}

// New returns an empty profile bound to the given identity public key.
func New(profileIdentity *identity.Identity) (*Profile, error) {
	if profileIdentity == nil {
		return nil, errors.New("profile: identity required")
	}
	pub, err := profileIdentity.PublicKeyBase64()
	if err != nil {
		return nil, err
	}
	return &Profile{
		state: StateUnregistered,
		key:   pub,
	}, nil
}

// SetWireGuardPublicKey records the current WireGuard public key. Called after
// key generation or rotation so the profile and keychain stay consistent.
func (p *Profile) SetWireGuardPublicKey(pub []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]byte, len(pub))
	copy(cp, pub)
	p.wireGuardPubKey = cp
}

// WireGuardPublicKey returns the current WireGuard public key bytes.
func (p *Profile) WireGuardPublicKey() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	cp := make([]byte, len(p.wireGuardPubKey))
	copy(cp, p.wireGuardPubKey)
	return cp
}

// Key returns the base64 SPKI Hub identity public key.
func (p *Profile) Key() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.key
}

// State returns the current lifecycle state.
func (p *Profile) State() State {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// SetState transitions the lifecycle state.
func (p *Profile) SetState(state State) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = state
}

// BeginRegistration marks the profile as registering and stamps the attempt.
func (p *Profile) BeginRegistration() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = StateRegistering
	p.registeredAt = time.Time{}
}

// ConfirmRegistration records a successful registration response from Hub. The
// Hub MAY echo its signing key (hubKey) and network identifier so the agent can
// construct a grant.LocalBinding without a separate trust channel; when the Hub
// omits them they are seeded from the first signature-verified grant, since the
// grant can only validate against the Hub key that signed it.
func (p *Profile) ConfirmRegistration(overlayAddress, hubNetworkID string, generation uint64, hubKey ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = StateRegistered
	p.registeredAt = time.Now()
	p.overlayAddress = overlayAddress
	if hubNetworkID != "" {
		p.hubNetworkID = hubNetworkID
	}
	if len(hubKey) > 0 && hubKey[0] != "" {
		p.hubKey = hubKey[0]
	}
	p.generation = generation
}

// SetOverlayIPv6 records the IPv6 overlay address the Hub assigned at
// registration (empty when it assigned none).
func (p *Profile) SetOverlayIPv6(address string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.overlayIPv6 = address
}

// HubKey returns the trusted Hub signing key learned at registration or seeded
// from the first verified grant. Empty until the Hub has been contacted.
func (p *Profile) HubKey() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.hubKey
}

// SetHubTrust seeds the Hub signing key and network identifier from a
// signature-verified grant. The grant's signature is the proof of Hub origin,
// so adopting its hubKey/hubNetworkId does not widen trust. Empty values are
// ignored so a partial seed cannot erase trusted state.
func (p *Profile) SetHubTrust(hubKey, hubNetworkID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if hubKey != "" {
		p.hubKey = hubKey
	}
	if hubNetworkID != "" {
		p.hubNetworkID = hubNetworkID
	}
}

// MarkRevoked records Hub-side revocation.
func (p *Profile) MarkRevoked() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = StateRevoked
}

// RotateWireGuardPublicKey swaps the active WireGuard public key without
// touching the profile identity. The Hub binds the new key through the next
// short-lived grant after the agent re-registers (or Hub pushes a generation
// update). Old sessions expire as their grants lapse.
func (p *Profile) RotateWireGuardPublicKey(newPublic []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]byte, len(newPublic))
	copy(cp, newPublic)
	p.wireGuardPubKey = cp
}

// Snapshot is an immutable view of the profile at a point in time.
type Snapshot struct {
	State           State
	Key             string
	WireGuardPubKey []byte
	RegisteredAt    time.Time
	Generation      uint64
	OverlayAddress  string
	// OverlayIPv6 is the IPv6 overlay address the Hub assigned, if any.
	OverlayIPv6  string
	HubNetworkID string
	HubKey       string
}

// Snapshot returns an immutable copy of the profile state.
func (p *Profile) Snapshot() Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	wg := make([]byte, len(p.wireGuardPubKey))
	copy(wg, p.wireGuardPubKey)
	return Snapshot{
		State:           p.state,
		Key:             p.key,
		WireGuardPubKey: wg,
		RegisteredAt:    p.registeredAt,
		Generation:      p.generation,
		OverlayAddress:  p.overlayAddress,
		OverlayIPv6:     p.overlayIPv6,
		HubNetworkID:    p.hubNetworkID,
		HubKey:          p.hubKey,
	}
}
