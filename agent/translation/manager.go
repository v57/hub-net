package translation

import (
	"errors"
	"fmt"
	"sync"
)

// Manager couples allocation and platform installation. Failed install rolls
// back platform state and releases claim; cleanup never affects siblings.
type Manager struct {
	mu        sync.Mutex
	allocator *Allocator
	backend   Backend
	active    map[string]active
}

type active struct {
	interfaceName string
	allocation    Allocation
}

func NewManager(allocator *Allocator, backend Backend) (*Manager, error) {
	if allocator == nil || backend == nil {
		return nil, errors.New("translation: allocator and backend required")
	}
	return &Manager{allocator: allocator, backend: backend, active: make(map[string]active)}, nil
}

// Reserve claims or reuses addressing without installing platform state.
func (m *Manager) Reserve(membershipID, persistedIPv4, persistedIPv6 string) (Allocation, error) {
	return m.allocator.Allocate(membershipID, persistedIPv4, persistedIPv6)
}

// CleanStale removes exact persisted platform state before restart probing.
func (m *Manager) CleanStale(interfaceName, persistedIPv4, persistedIPv6 string) error {
	if persistedIPv4 == "" && persistedIPv6 == "" {
		return nil
	}
	allocation, err := parseAllocation(persistedIPv4, persistedIPv6)
	if err != nil {
		return err
	}
	return m.backend.Remove(interfaceName, allocation)
}

func (m *Manager) Activate(membershipID, interfaceName, persistedIPv4, persistedIPv6 string) (Allocation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.active[membershipID]; ok {
		if current.interfaceName != interfaceName {
			return Allocation{}, errors.New("translation: membership active on different interface")
		}
		// WireGuard replacement on reconnect may remove routes bound to its
		// prior link. Platform install is idempotent and repairs that state.
		if err := m.backend.Install(interfaceName, current.allocation); err != nil {
			return Allocation{}, fmt.Errorf("translation: reinstall: %w", err)
		}
		return current.allocation, nil
	}
	if interfaceName == "" {
		return Allocation{}, errors.New("translation: interface name required")
	}
	allocation, err := m.allocator.Allocate(membershipID, persistedIPv4, persistedIPv6)
	if err != nil {
		return Allocation{}, err
	}
	if err := m.backend.Install(interfaceName, allocation); err != nil {
		_ = m.backend.Remove(interfaceName, allocation)
		m.allocator.Release(membershipID)
		return Allocation{}, fmt.Errorf("translation: install: %w", err)
	}
	m.active[membershipID] = active{interfaceName: interfaceName, allocation: allocation}
	return allocation, nil
}

func (m *Manager) Deactivate(membershipID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.active[membershipID]
	if !ok {
		m.allocator.Release(membershipID)
		return nil
	}
	if err := m.backend.Remove(current.interfaceName, current.allocation); err != nil {
		return fmt.Errorf("translation: remove: %w", err)
	}
	delete(m.active, membershipID)
	m.allocator.Release(membershipID)
	return nil
}

// DeactivateAll removes every owned rule set independently and returns joined
// cleanup errors after attempting all memberships.
func (m *Manager) DeactivateAll() error {
	m.mu.Lock()
	ids := make([]string, 0, len(m.active))
	for id := range m.active {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	var result error
	for _, id := range ids {
		result = errors.Join(result, m.Deactivate(id))
	}
	return result
}
