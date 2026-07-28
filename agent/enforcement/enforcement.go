// Package enforcement owns fail-closed per-resource transport authorization.
package enforcement

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/v57/hub-service-go/protocol"
)

var ErrInvalidAuthorization = errors.New("enforcement: invalid authorization")
var ErrPlatformUnsupported = errors.New("enforcement: platform backend unsupported")

// Rule is the exact signed flow boundary installed in the platform firewall.
type Rule struct {
	ResourceID      string
	ProviderID      string
	Source          netip.Addr
	Destination     netip.Addr
	DestinationPort uint16
	Protocol        string
	Generation      uint64
	ExpiresAt       time.Time
}

// Backend atomically applies rules and terminates matching tracked flows.
// Platform-specific packet filtering is wired by HN-311.
type Backend interface {
	ReplaceRules([]Rule) error
	TerminateResource(resourceID string) error
}

// NewPlatformBackend returns the host firewall backend. interfaceName is the
// WireGuard interface whose inbound overlay traffic is protected.
func NewPlatformBackend(interfaceName string) (Backend, error) {
	if interfaceName == "" {
		return nil, ErrInvalidAuthorization
	}
	return newPlatformBackend(interfaceName)
}

type Manager struct {
	mu      sync.Mutex
	backend Backend
	now     func() time.Time
	rules   map[string]Rule
}

func New(backend Backend) (*Manager, error) {
	if backend == nil {
		return nil, errors.New("enforcement: backend required")
	}
	return &Manager{backend: backend, now: time.Now, rules: make(map[string]Rule)}, nil
}

// Authorize installs one already signature-verified grant. Every packet field
// is bound to signed data; callers cannot widen source, protocol, address, or port.
func (m *Manager) Authorize(grant protocol.ConnectionGrant) error {
	source, err := parseOverlayHost(grant.CallerAddress)
	if err != nil {
		return err
	}
	destination, err := parseOverlayHost(grant.DestinationAddress)
	if err != nil || source.Is4() != destination.Is4() ||
		(grant.Protocol != "tcp" && grant.Protocol != "udp") ||
		grant.DestinationPort == 0 || grant.ResourceID == "" ||
		grant.ProviderID == "" {
		return ErrInvalidAuthorization
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil || !expiresAt.After(m.now()) {
		return ErrInvalidAuthorization
	}
	rule := Rule{
		ResourceID: grant.ResourceID, ProviderID: grant.ProviderID,
		Source: source, Destination: destination,
		DestinationPort: grant.DestinationPort, Protocol: grant.Protocol,
		Generation: grant.Generation, ExpiresAt: expiresAt,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	previousRules := cloneRules(m.rules)
	m.pruneLocked()
	key := ruleKey(rule)
	m.rules[key] = rule
	if err := m.applyLocked(); err != nil {
		m.rules = previousRules
		return fmt.Errorf("enforcement: install rule: %w", err)
	}
	return nil
}

// UpdateGeneration removes all older authorization. Immediate mode also asks
// backend to kill matching established TCP/UDP flow state.
func (m *Manager) UpdateGeneration(resourceID string, generation uint64, immediate bool) error {
	if resourceID == "" {
		return ErrInvalidAuthorization
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previousRules := cloneRules(m.rules)
	m.pruneLocked()
	for key, rule := range m.rules {
		if rule.ResourceID == resourceID && rule.Generation < generation {
			delete(m.rules, key)
		}
	}
	if err := m.applyLocked(); err != nil {
		m.rules = previousRules
		return fmt.Errorf("enforcement: revoke rules: %w", err)
	}
	if immediate {
		if err := m.backend.TerminateResource(resourceID); err != nil {
			return fmt.Errorf("enforcement: terminate flows: %w", err)
		}
	}
	return nil
}

// PruneExpired removes expired authorization from the platform firewall.
// Callers should invoke this from their runtime expiry timer even when no new
// grants or generation updates arrive.
func (m *Manager) PruneExpired() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previousRules := cloneRules(m.rules)
	if !m.pruneLocked() {
		return nil
	}
	if err := m.applyLocked(); err != nil {
		m.rules = previousRules
		return fmt.Errorf("enforcement: prune expired rules: %w", err)
	}
	return nil
}

// RunExpiryLoop removes expired authorization even when no grants or
// generation updates arrive. It blocks until cancellation or a backend error.
// One loop should run for each active Manager.
func (m *Manager) RunExpiryLoop(ctx context.Context, interval time.Duration) error {
	if ctx == nil || interval <= 0 {
		return ErrInvalidAuthorization
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := m.PruneExpired(); err != nil {
				return err
			}
		}
	}
}

func (m *Manager) Rules() []Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	return m.snapshotLocked()
}

func (m *Manager) pruneLocked() bool {
	changed := false
	now := m.now()
	for key, rule := range m.rules {
		if !rule.ExpiresAt.After(now) {
			delete(m.rules, key)
			changed = true
		}
	}
	return changed
}

func (m *Manager) applyLocked() error { return m.backend.ReplaceRules(m.snapshotLocked()) }

func (m *Manager) snapshotLocked() []Rule {
	rules := make([]Rule, 0, len(m.rules))
	for _, rule := range m.rules {
		rules = append(rules, rule)
	}
	slices.SortFunc(rules, func(left, right Rule) int {
		return compareRuleKeys(ruleKey(left), ruleKey(right))
	})
	return rules
}

func cloneRules(rules map[string]Rule) map[string]Rule {
	cloned := make(map[string]Rule, len(rules))
	for key, rule := range rules {
		cloned[key] = rule
	}
	return cloned
}

func compareRuleKeys(left, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func ruleKey(rule Rule) string {
	return fmt.Sprintf("%s|%s|%s|%s|%d", rule.ResourceID, rule.Protocol, rule.Source, rule.Destination, rule.DestinationPort)
}

func parseOverlayHost(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, ErrInvalidAuthorization
	}
	if !address.Is4() && !address.Is6() {
		return netip.Addr{}, ErrInvalidAuthorization
	}
	return address, nil
}

// MemoryBackend is deterministic test/local state. It defaults to deny:
// Allowed returns true only for an exact installed tuple.
type MemoryBackend struct {
	mu         sync.Mutex
	rules      []Rule
	terminated []string
}

func (b *MemoryBackend) ReplaceRules(rules []Rule) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rules = append([]Rule(nil), rules...)
	return nil
}

func (b *MemoryBackend) TerminateResource(resourceID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.terminated = append(b.terminated, resourceID)
	return nil
}

func (b *MemoryBackend) Allowed(protocolName string, source, destination netip.Addr, port uint16, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, rule := range b.rules {
		if rule.Protocol == protocolName && rule.Source == source &&
			rule.Destination == destination && rule.DestinationPort == port &&
			rule.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}

func (b *MemoryBackend) Terminated() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.terminated...)
}
