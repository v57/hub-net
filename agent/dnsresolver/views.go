package dnsresolver

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/v57/hub-net/translation"
)

// ViewSet combines isolated per-Hub resource views behind one reserved-suffix
// resolver. Every published name is qualified by its stable local Hub alias.
type ViewSet struct {
	mu       sync.Mutex
	resolver *Resolver
	views    map[string]map[string]Lookup
}

func NewViewSet(resolver *Resolver) (*ViewSet, error) {
	if resolver == nil {
		return nil, errors.New("dnsresolver: resolver required")
	}
	return &ViewSet{resolver: resolver, views: make(map[string]map[string]Lookup)}, nil
}

// Qualify inserts alias immediately before the reserved suffix.
func Qualify(authority, alias string) (string, error) {
	name, ok := canonicalHubName(authority)
	if !ok || name == Suffix {
		return "", fmt.Errorf("dnsresolver: invalid authority %q", authority)
	}
	alias = strings.ToLower(strings.TrimSpace(alias))
	if !validAlias(alias) {
		return "", fmt.Errorf("dnsresolver: invalid Hub alias %q", alias)
	}
	base := strings.TrimSuffix(name, "."+Suffix)
	return base + "." + alias + "." + Suffix, nil
}

// Replace atomically replaces one Hub's complete permission-filtered view.
// Canonical overlay addresses are translated without changing their host bits.
func (v *ViewSet) Replace(alias string, records map[string]Lookup, ipv4, ipv6 netip.Prefix) error {
	if err := validatePrefixes(ipv4, ipv6); err != nil {
		return err
	}
	next := make(map[string]Lookup, len(records))
	for authority, record := range records {
		qualified, err := Qualify(authority, alias)
		if err != nil {
			return err
		}
		if record.ResourceID == "" {
			return fmt.Errorf("dnsresolver: authority %q has empty resource ID", authority)
		}
		translated := Lookup{ResourceID: record.ResourceID}
		for _, address := range record.Addresses {
			parsed, ok := netip.AddrFromSlice(address)
			if !ok {
				return fmt.Errorf("dnsresolver: authority %q has invalid address", authority)
			}
			parsed = parsed.Unmap()
			var mapped netip.Addr
			switch {
			case translation.CanonicalIPv4.Contains(parsed):
				mapped, err = translation.TranslateSource(parsed, translation.CanonicalIPv4, ipv4)
			case translation.CanonicalIPv6.Contains(parsed):
				mapped, err = translation.TranslateSource(parsed, translation.CanonicalIPv6, ipv6)
			default:
				err = fmt.Errorf("address %s outside canonical overlay", parsed)
			}
			if err != nil {
				return fmt.Errorf("dnsresolver: authority %q: %w", authority, err)
			}
			translated.Addresses = append(translated.Addresses, net.IP(mapped.AsSlice()))
		}
		next[qualified] = translated
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	candidate := make(map[string]map[string]Lookup, len(v.views)+1)
	for key, view := range v.views {
		candidate[key] = view
	}
	candidate[strings.ToLower(strings.TrimSpace(alias))] = next
	if err := v.replaceResolver(candidate); err != nil {
		return err
	}
	v.views = candidate
	return nil
}

// Remove drops exactly one Hub view without disturbing sibling Hubs.
func (v *ViewSet) Remove(alias string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	alias = strings.ToLower(strings.TrimSpace(alias))
	candidate := make(map[string]map[string]Lookup, len(v.views))
	for key, view := range v.views {
		if key != alias {
			candidate[key] = view
		}
	}
	if err := v.replaceResolver(candidate); err != nil {
		return err
	}
	v.views = candidate
	return nil
}

func (v *ViewSet) replaceResolver(views map[string]map[string]Lookup) error {
	all := make(map[string]Lookup)
	for _, view := range views {
		for authority, record := range view {
			if _, exists := all[authority]; exists {
				return fmt.Errorf("dnsresolver: duplicate qualified authority %q", authority)
			}
			all[authority] = record
		}
	}
	return v.resolver.Replace(all)
}

func validatePrefixes(ipv4, ipv6 netip.Prefix) error {
	if ipv4.Bits() != translation.CanonicalIPv4.Bits() || !translation.IPv4Pool.Contains(ipv4.Addr()) {
		return errors.New("dnsresolver: invalid translated IPv4 prefix")
	}
	if ipv6.Bits() != translation.CanonicalIPv6.Bits() || !translation.IPv6Pool.Contains(ipv6.Addr()) {
		return errors.New("dnsresolver: invalid translated IPv6 prefix")
	}
	return nil
}

func validAlias(alias string) bool {
	if alias == "" || len(alias) > 63 || alias[0] == '-' || alias[len(alias)-1] == '-' {
		return false
	}
	for _, character := range alias {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}
