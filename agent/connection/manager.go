// Package connection orchestrates direct, grant-authorized WireGuard peers.
package connection

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/v57/hub-net/grant"
	"github.com/v57/hub-net/wireguard"
	"github.com/v57/hub-service-go/protocol"
)

var ErrDirectFailed = errors.New("connection: direct establishment failed")

// CandidateChecker performs a bounded reachability check. Candidate delivery
// is transport metadata only and never grants network access.
type CandidateChecker interface {
	Check(context.Context, protocol.Candidate) error
}

// HandshakeChecker confirms that WireGuard completed a handshake with peer.
type HandshakeChecker interface {
	Wait(context.Context, []byte) error
}

type Diagnostic struct {
	ResourceID string    `json:"resourceId"`
	ProviderID string    `json:"providerId"`
	Code       string    `json:"code"`
	Message    string    `json:"message"`
	Attempts   int       `json:"attempts"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type Peer struct {
	ResourceID string
	ProviderID string
	PublicKey  []byte
	Endpoint   string
	LastUsed   time.Time
}

type Options struct {
	Adapter          wireguard.Adapter
	Verifier         *grant.Verifier
	CandidateChecker CandidateChecker
	HandshakeChecker HandshakeChecker
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	Now              func() time.Time
}

type Manager struct {
	mu         sync.Mutex
	adapter    wireguard.Adapter
	verifier   *grant.Verifier
	candidates CandidateChecker
	handshake  HandshakeChecker
	timeout    time.Duration
	idle       time.Duration
	now        func() time.Time
	peers      map[string]Peer
	history    []Diagnostic
}

func New(options Options) (*Manager, error) {
	if options.Adapter == nil || options.Verifier == nil ||
		options.CandidateChecker == nil || options.HandshakeChecker == nil {
		return nil, errors.New("connection: adapter, verifier, candidate checker, and handshake checker required")
	}
	if options.HandshakeTimeout <= 0 || options.IdleTimeout <= 0 {
		return nil, errors.New("connection: positive handshake and idle timeouts required")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{
		adapter: options.Adapter, verifier: options.Verifier,
		candidates: options.CandidateChecker, handshake: options.HandshakeChecker,
		timeout: options.HandshakeTimeout, idle: options.IdleTimeout, now: now,
		peers: make(map[string]Peer),
	}, nil
}

// Connect validates grant once, tries direct candidates by priority, and
// accepts only a confirmed WireGuard handshake. No relay fallback exists.
func (m *Manager) Connect(ctx context.Context, connectionGrant protocol.ConnectionGrant, candidates []protocol.Candidate) error {
	if err := m.verifier.Verify(connectionGrant); err != nil {
		return err
	}
	publicKey, err := base64.StdEncoding.DecodeString(connectionGrant.TargetWireGuardKey)
	if err != nil || len(publicKey) != 32 {
		return fmt.Errorf("%w: target key", ErrDirectFailed)
	}
	address, err := netip.ParseAddr(connectionGrant.DestinationAddress)
	if err != nil {
		return fmt.Errorf("%w: destination", ErrDirectFailed)
	}
	bits := 128
	if address.Is4() {
		bits = 32
	}

	usable := make([]protocol.Candidate, 0, len(candidates))
	now := m.now()
	for _, candidate := range candidates {
		if validCandidate(candidate, connectionGrant.TargetAgentKey, now) {
			usable = append(usable, candidate)
		}
	}
	slices.SortStableFunc(usable, func(a, b protocol.Candidate) int {
		switch {
		case a.Priority > b.Priority:
			return -1
		case a.Priority < b.Priority:
			return 1
		default:
			return 0
		}
	})

	attemptCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	attempts := 0
	var lastErr error
	for _, candidate := range usable {
		if err := attemptCtx.Err(); err != nil {
			lastErr = err
			break
		}
		attempts++
		if err := m.candidates.Check(attemptCtx, candidate); err != nil {
			lastErr = err
			continue
		}
		endpoint := netip.AddrPortFrom(netip.MustParseAddr(candidate.Address), candidate.Port).String()
		if err := m.adapter.AddPeer(wireguard.PeerConfig{
			PublicKey:  publicKey,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(address, bits)},
			Endpoint:   endpoint,
		}); err != nil {
			lastErr = err
			continue
		}
		if err := m.handshake.Wait(attemptCtx, publicKey); err != nil {
			_ = m.adapter.RemovePeer(publicKey)
			lastErr = err
			continue
		}
		m.mu.Lock()
		m.peers[string(publicKey)] = Peer{
			ResourceID: connectionGrant.ResourceID, ProviderID: connectionGrant.ProviderID,
			PublicKey: append([]byte(nil), publicKey...), Endpoint: endpoint, LastUsed: m.now(),
		}
		m.recordLocked(Diagnostic{
			ResourceID: connectionGrant.ResourceID, ProviderID: connectionGrant.ProviderID,
			Code: "direct_connected", Message: "direct WireGuard handshake established",
			Attempts: attempts, UpdatedAt: m.now(),
		})
		m.mu.Unlock()
		return nil
	}
	m.mu.Lock()
	message := "no valid direct candidate"
	if lastErr != nil {
		message = "candidate checks or WireGuard handshake failed"
	}
	m.recordLocked(Diagnostic{
		ResourceID: connectionGrant.ResourceID, ProviderID: connectionGrant.ProviderID,
		Code: "direct_connect_failed", Message: message, Attempts: attempts, UpdatedAt: m.now(),
	})
	m.mu.Unlock()
	return fmt.Errorf("%w after %d candidate attempts", ErrDirectFailed, attempts)
}

func validCandidate(candidate protocol.Candidate, targetAgentKey string, now time.Time) bool {
	if candidate.Version != protocol.WireVersion || candidate.CandidateID == "" ||
		candidate.SessionID == "" || candidate.AgentKey != targetAgentKey ||
		candidate.Transport != "udp" || candidate.Port == 0 {
		return false
	}
	address, err := netip.ParseAddr(candidate.Address)
	if err != nil || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, candidate.ExpiresAt)
	return err == nil && expires.After(now)
}

func (m *Manager) Touch(publicKey []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	peer, ok := m.peers[string(publicKey)]
	if ok {
		peer.LastUsed = m.now()
		m.peers[string(publicKey)] = peer
	}
	return ok
}

func (m *Manager) PruneIdle() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := m.now().Add(-m.idle)
	for key, peer := range m.peers {
		if peer.LastUsed.After(cutoff) {
			continue
		}
		if err := m.adapter.RemovePeer(peer.PublicKey); err != nil {
			return fmt.Errorf("connection: remove idle peer: %w", err)
		}
		delete(m.peers, key)
		m.recordLocked(Diagnostic{
			ResourceID: peer.ResourceID, ProviderID: peer.ProviderID,
			Code: "peer_idle_removed", Message: "idle peer state removed", UpdatedAt: m.now(),
		})
	}
	return nil
}

func (m *Manager) RunCleanup(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("connection: positive cleanup interval required")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := m.PruneIdle(); err != nil {
				return err
			}
		}
	}
}

func (m *Manager) Peers() []Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Peer, 0, len(m.peers))
	for _, peer := range m.peers {
		peer.PublicKey = append([]byte(nil), peer.PublicKey...)
		out = append(out, peer)
	}
	return out
}

func (m *Manager) Diagnostics() []Diagnostic {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Diagnostic(nil), m.history...)
}

func (m *Manager) recordLocked(diagnostic Diagnostic) {
	const maxDiagnostics = 64
	m.history = append(m.history, diagnostic)
	if len(m.history) > maxDiagnostics {
		m.history = append([]Diagnostic(nil), m.history[len(m.history)-maxDiagnostics:]...)
	}
}
