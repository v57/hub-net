// Package grant verifies Hub connection grants and configures authorized
// outbound WireGuard peers.
package grant

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	protocol "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net/wireguard"
)

var (
	ErrInvalidGrant    = errors.New("grant: invalid connection grant")
	ErrBindingMismatch = errors.New("grant: connection grant binding mismatch")
	ErrReplay          = errors.New("grant: connection grant already consumed")
)

// LocalBinding is trusted state established by profile registration. Values
// from an unverified grant must never populate this structure.
type LocalBinding struct {
	HubKey             string
	HubNetworkID       string
	CallerKey          string
	CallerWireGuardKey string
	// CallerMemberKey is the caller's device member key (`device:<id>`),
	// which hubs that key members by device may name instead of CallerKey.
	CallerMemberKey string
}

// GenerationLookup returns the current authorization generation for a
// resource. Missing resources fail closed.
type GenerationLookup func(resourceID string) (uint64, bool)

// Verifier validates and consumes short-lived grants.
type Verifier struct {
	mu          sync.Mutex
	local       LocalBinding
	generations GenerationLookup
	now         func() time.Time
	consumed    map[string]time.Time
}

func NewVerifier(local LocalBinding, generations GenerationLookup) (*Verifier, error) {
	if local.HubKey == "" || local.HubNetworkID == "" ||
		local.CallerKey == "" || local.CallerWireGuardKey == "" {
		return nil, fmt.Errorf("%w: incomplete local binding", ErrBindingMismatch)
	}
	if _, err := parseEd25519PublicKey(local.HubKey); err != nil {
		return nil, fmt.Errorf("%w: trusted Hub key: %v", ErrBindingMismatch, err)
	}
	if _, err := decodeWireGuardKey(local.CallerWireGuardKey); err != nil {
		return nil, fmt.Errorf("%w: local WireGuard key: %v", ErrBindingMismatch, err)
	}
	if generations == nil {
		return nil, fmt.Errorf("%w: generation lookup required", ErrBindingMismatch)
	}
	return &Verifier{
		local:       local,
		generations: generations,
		now:         time.Now,
		consumed:    make(map[string]time.Time),
	}, nil
}

// Verify validates trusted identity, signature, lifetime, caller/target
// bindings, protocol, destination, and current resource generation. A grant
// is one-use; failed validation never consumes it.
func (v *Verifier) Verify(grant protocol.ConnectionGrant) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.now()
	for id, expiry := range v.consumed {
		if !expiry.After(now) {
			delete(v.consumed, id)
		}
	}
	if grant.Version != protocol.WireVersion || grant.GrantID == "" ||
		grant.ResourceID == "" || grant.ProviderID == "" ||
		(grant.Protocol != "tcp" && grant.Protocol != "udp") ||
		grant.DestinationPort == 0 || grant.TargetKey == "" {
		return ErrInvalidGrant
	}
	if grant.HubKey != v.local.HubKey ||
		grant.HubNetworkID != v.local.HubNetworkID ||
		(grant.CallerKey != v.local.CallerKey && (v.local.CallerMemberKey == "" || grant.CallerKey != v.local.CallerMemberKey)) ||
		grant.CallerWireGuardKey != v.local.CallerWireGuardKey {
		return ErrBindingMismatch
	}
	if _, exists := v.consumed[grant.GrantID]; exists {
		return ErrReplay
	}
	generation, ok := v.generations(grant.ResourceID)
	if !ok || generation != grant.Generation {
		return ErrBindingMismatch
	}
	if !protocol.HasValidLifetime(
		grant.IssuedAt,
		grant.ExpiresAt,
		protocol.ConnectionGrantMaxLifetime,
		now,
	) {
		return ErrInvalidGrant
	}
	hubKey, err := parseEd25519PublicKey(grant.HubKey)
	if err != nil {
		return ErrInvalidGrant
	}
	valid, err := protocol.VerifyEnvelope(
		protocol.PurposeConnectionGrant,
		grant,
		hubKey,
		grant.Signature,
	)
	if err != nil || !valid {
		return ErrInvalidGrant
	}
	if _, err := targetPrefix(grant.DestinationAddress); err != nil {
		return err
	}
	if _, err := targetPrefix(grant.CallerAddress); err != nil {
		return err
	}
	if _, err := decodeWireGuardKey(grant.TargetWireGuardKey); err != nil {
		return ErrInvalidGrant
	}
	expires, _ := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	v.consumed[grant.GrantID] = expires
	return nil
}

// ConfigureOutbound verifies grant then adds exactly its authorized target
// key and destination overlay address. Endpoint comes from candidate checks
// and is not trusted as authorization input.
func (v *Verifier) ConfigureOutbound(
	adapter wireguard.Adapter,
	grant protocol.ConnectionGrant,
	endpoint string,
) error {
	if adapter == nil {
		return errors.New("grant: wireguard adapter required")
	}
	if err := v.Verify(grant); err != nil {
		return err
	}
	publicKey, _ := decodeWireGuardKey(grant.TargetWireGuardKey)
	allowed, _ := targetPrefix(grant.DestinationAddress)
	if err := adapter.AddPeer(wireguard.PeerConfig{
		PublicKey:  publicKey,
		AllowedIPs: []netip.Prefix{allowed},
		Endpoint:   endpoint,
	}); err != nil {
		return fmt.Errorf("grant: configure peer: %w", err)
	}
	return nil
}

func targetPrefix(value string) (netip.Prefix, error) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, ErrInvalidGrant
	}
	bits := 128
	if address.Is4() {
		bits = 32
	}
	prefix := netip.PrefixFrom(address, bits)
	if err := wireguard.ValidateAllowedIPs([]netip.Prefix{prefix}); err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %v", ErrInvalidGrant, err)
	}
	return prefix, nil
}

func decodeWireGuardKey(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("expected base64 32-byte key")
	}
	return raw, nil
}

func parseEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not Ed25519")
	}
	return publicKey, nil
}
