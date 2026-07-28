// Package wireguard abstracts the platform WireGuard implementation.
//
// HN-303 introduces a portable Adapter interface; concrete kernel/userspace
// adapters (Linux netlink, macOS privileged helper, WireGuardNT) ship in
// later platform tasks. The scaffold defines the interface, an in-memory fake
// for deterministic config tests, and the overlay/route constraints every
// adapter must respect (see PLATFORMS.md and protocol-foundations.md).
package wireguard

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// IPv4OverlayPrefix is the agent-managed IPv4 overlay. Frozen in
// protocol-foundations.md: 100.96.0.0/11.
var IPv4OverlayPrefix = netip.MustParsePrefix("100.96.0.0/11")

// IPv6OverlayPrefix is the agent-managed IPv6 overlay.
var IPv6OverlayPrefix = netip.MustParsePrefix("fd48:5542:4e45::/48")

// IPv4InfrastructureReserved is reserved for future protocol infrastructure.
var IPv4InfrastructureReserved = netip.MustParsePrefix("100.127.255.0/24")

// IPv6InfrastructureReserved is reserved for future protocol infrastructure.
var IPv6InfrastructureReserved = netip.MustParsePrefix("fd48:5542:4e45:ffff::/64")

// DefaultPort is the default listen port when none is configured.
const DefaultPort = 51820

// PeerConfig describes an authorized WireGuard peer.
type PeerConfig struct {
	// PublicKey is the peer Curve25519 public key, 32 raw bytes.
	PublicKey []byte
	// AllowedIPs restricts the overlay addresses the peer may source.
	AllowedIPs []netip.Prefix
	// Endpoint is an optional peer UDP endpoint for active sessions.
	Endpoint string
}

// InterfaceConfig is the full per-profile WireGuard interface configuration.
type InterfaceConfig struct {
	// Name is the OS interface name (e.g. "hubnet0", "utun8").
	Name string
	// PrivateKey is the agent Curve25519 private key, 32 raw bytes.
	PrivateKey []byte
	// Address is the agent overlay address.
	Address netip.Addr
	// ListenPort is the UDP listen port.
	ListenPort uint16
	// Peers are the currently configured peers.
	Peers []PeerConfig
}

// Adapter is the portable WireGuard lifecycle interface. Implementations MUST
// reject interface configurations that would route 0.0.0.0/0 or ::/0, and MUST
// refuse to install routes outside the overlay prefixes declared above.
type Adapter interface {
	// Up brings the interface up with the given configuration.
	Up(config InterfaceConfig) error
	// Down tears the interface down and removes routes/firewall state.
	Down() error
	// AddPeer configures a peer on demand.
	AddPeer(peer PeerConfig) error
	// RemovePeer removes a peer and its firewall state.
	RemovePeer(publicKey []byte) error
	// State reports the current interface configuration, if up.
	State() (InterfaceConfig, bool)
}

// ErrForbiddenRoute signals an adapter refused a route outside the overlay.
var ErrForbiddenRoute = errors.New("wireguard: route outside overlay prefixes")

// ErrDefaultRoute signals an adapter refused to install a default route.
var ErrDefaultRoute = errors.New("wireguard: refusing default route")

// ErrOverlayRouteConflict signals an adapter refused to start because an
// existing route already covers a Hub Network overlay prefix (HN-304). The
// agent fails closed rather than silently layering a more-specific route on
// top of unknown infrastructure.
var ErrOverlayRouteConflict = errors.New("wireguard: overlay prefix overlaps existing route")

// ValidateAllowedIPs enforces the overlay boundary. Every AllowedIPs entry
// must sit inside IPv4OverlayPrefix or IPv6OverlayPrefix and must not equal
// the default route. Returns ErrForbiddenRoute or ErrDefaultRoute on violation.
func ValidateAllowedIPs(allowed []netip.Prefix) error {
	for _, prefix := range allowed {
		if prefix.Bits() == 0 {
			return ErrDefaultRoute
		}
		inside := IPv4OverlayPrefix.Contains(prefix.Addr()) ||
			IPv6OverlayPrefix.Contains(prefix.Addr())
		if !inside {
			return fmt.Errorf("%w: %s", ErrForbiddenRoute, prefix)
		}
		if prefix.Overlaps(IPv4InfrastructureReserved) ||
			prefix.Overlaps(IPv6InfrastructureReserved) {
			return fmt.Errorf("%w: overlaps reserved %s", ErrForbiddenRoute, prefix)
		}
	}
	return nil
}

// FakeAdapter is an in-memory Adapter for deterministic config tests and for
// running the agent on unsupported platforms where real tunnel setup fails.
// It records the sequence of operations so tests can assert behavior.
type FakeAdapter struct {
	mu      sync.Mutex
	up      bool
	config  InterfaceConfig
	peers   map[string]PeerConfig
	upErr   error
	peerErr error
}

// NewFakeAdapter returns an empty FakeAdapter.
func NewFakeAdapter() *FakeAdapter {
	return &FakeAdapter{peers: make(map[string]PeerConfig)}
}

// SetUpError configures the next Up call to fail with err.
func (f *FakeAdapter) SetUpError(err error) { f.upErr = err }

// SetPeerError configures the next AddPeer/RemovePeer to fail with err.
func (f *FakeAdapter) SetPeerError(err error) { f.peerErr = err }

// Up records the configuration and validates AllowedIPs.
func (f *FakeAdapter) Up(config InterfaceConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upErr != nil {
		err := f.upErr
		f.upErr = nil
		return err
	}
	if err := ValidateAllowedIPs(collectAllowedIPs(config.Peers)); err != nil {
		return err
	}
	f.config = config
	f.peers = make(map[string]PeerConfig, len(config.Peers))
	for _, peer := range config.Peers {
		f.peers[string(peer.PublicKey)] = peer
	}
	f.up = true
	return nil
}

// Down removes all state.
func (f *FakeAdapter) Down() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.up = false
	f.peers = make(map[string]PeerConfig)
	return nil
}

// AddPeer validates and records the peer.
func (f *FakeAdapter) AddPeer(peer PeerConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.peerErr != nil {
		err := f.peerErr
		f.peerErr = nil
		return err
	}
	if err := ValidateAllowedIPs(peer.AllowedIPs); err != nil {
		return err
	}
	f.peers[string(peer.PublicKey)] = peer
	return nil
}

// RemovePeer drops the peer.
func (f *FakeAdapter) RemovePeer(publicKey []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.peerErr != nil {
		err := f.peerErr
		f.peerErr = nil
		return err
	}
	delete(f.peers, string(publicKey))
	return nil
}

// State returns the recorded configuration when up.
func (f *FakeAdapter) State() (InterfaceConfig, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.up {
		return InterfaceConfig{}, false
	}
	config := f.config
	config.Peers = make([]PeerConfig, 0, len(f.peers))
	for _, peer := range f.peers {
		config.Peers = append(config.Peers, peer)
	}
	return config, true
}

func collectAllowedIPs(peers []PeerConfig) []netip.Prefix {
	out := make([]netip.Prefix, 0)
	for _, peer := range peers {
		out = append(out, peer.AllowedIPs...)
	}
	return out
}
