// Package dnsresolver implements hub-net's reserved-suffix DNS resolver.
//
// It is authoritative only for hub.invalid. Queries outside that suffix are
// delegated unchanged to the configured upstream, preserving ordinary DNS.
package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

const Suffix = "hub.invalid"

var (
	ErrInactive         = errors.New("dnsresolver: profile inactive")
	ErrNotHubName       = errors.New("dnsresolver: not a Hub Network name")
	ErrResourceNotFound = errors.New("dnsresolver: resource not found")
)

// Lookup is the result of a canonical authority lookup.
type Lookup struct {
	ResourceID string
	Addresses  []net.IP
}

// Resolver holds the permission-filtered authority view for one active
// profile. Hub stream consumers replace this view atomically.
type Resolver struct {
	mu      sync.RWMutex
	active  bool
	records map[string]Lookup
}

func New() *Resolver {
	return &Resolver{records: make(map[string]Lookup)}
}

// Replace atomically installs the complete visible resource view. Authorities
// are validated so display names cannot escape the reserved suffix.
func (r *Resolver) Replace(records map[string]Lookup) error {
	next := make(map[string]Lookup, len(records))
	for authority, record := range records {
		name, ok := canonicalHubName(authority)
		if !ok || name == Suffix {
			return fmt.Errorf("dnsresolver: invalid authority %q", authority)
		}
		if record.ResourceID == "" {
			return fmt.Errorf("dnsresolver: authority %q has empty resource ID", authority)
		}
		copied := Lookup{ResourceID: record.ResourceID}
		for _, address := range record.Addresses {
			if address == nil {
				return fmt.Errorf("dnsresolver: authority %q has invalid address", authority)
			}
			copied.Addresses = append(copied.Addresses, append(net.IP(nil), address...))
		}
		next[name] = copied
	}
	r.mu.Lock()
	r.records = next
	r.mu.Unlock()
	return nil
}

// Activate enables private resolution after profile authorization.
func (r *Resolver) Activate() {
	r.mu.Lock()
	r.active = true
	r.mu.Unlock()
}

// Deactivate immediately disables resolution and drops stale resource state.
func (r *Resolver) Deactivate() {
	r.mu.Lock()
	r.active = false
	r.records = make(map[string]Lookup)
	r.mu.Unlock()
}

// Lookup resolves one canonical Hub authority.
func (r *Resolver) Lookup(authority string) (Lookup, error) {
	name, ok := canonicalHubName(authority)
	if !ok {
		return Lookup{}, ErrNotHubName
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.active {
		return Lookup{}, ErrInactive
	}
	record, ok := r.records[name]
	if !ok {
		return Lookup{}, ErrResourceNotFound
	}
	result := Lookup{ResourceID: record.ResourceID}
	for _, address := range record.Addresses {
		result.Addresses = append(result.Addresses, append(net.IP(nil), address...))
	}
	return result, nil
}

// IsHubName reports whether name is at or below the reserved suffix. Matching
// is label-boundary aware: "nothub.invalid.example" is ordinary DNS.
func IsHubName(name string) bool {
	_, ok := canonicalHubName(name)
	return ok
}

func canonicalHubName(name string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == Suffix || strings.HasSuffix(name, "."+Suffix) {
		return name, true
	}
	return "", false
}

// Installer applies and removes platform split-DNS configuration. Concrete
// privileged implementations are supplied during packaging; tests and
// embedders can use MemoryInstaller.
type Installer interface {
	Install(context.Context, net.Addr, string) error
	Remove(context.Context) error
}

// MemoryInstaller records lifecycle without mutating host DNS settings.
type MemoryInstaller struct {
	mu        sync.Mutex
	Installed bool
	Address   net.Addr
	Suffix    string
}

func (i *MemoryInstaller) Install(_ context.Context, address net.Addr, suffix string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.Installed, i.Address, i.Suffix = true, address, suffix
	return nil
}

func (i *MemoryInstaller) Remove(context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.Installed, i.Address, i.Suffix = false, nil, ""
	return nil
}
