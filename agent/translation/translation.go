// Package translation allocates and owns device-local address spaces used to
// disambiguate overlapping Hub Network overlays.
package translation

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
)

var (
	// IPv4Pool is split into eight /11 slots, matching the canonical IPv4
	// overlay prefix length so host bits can be translated reversibly.
	IPv4Pool = netip.MustParsePrefix("10.0.0.0/8")
	// IPv6Pool is split into /48 slots, matching the canonical IPv6 overlay.
	IPv6Pool = netip.MustParsePrefix("fd80::/9")

	CanonicalIPv4 = netip.MustParsePrefix("100.96.0.0/11")
	CanonicalIPv6 = netip.MustParsePrefix("fd48:5542:4e45::/48")
)

var (
	ErrExhausted = errors.New("translation: address pool exhausted")
	ErrConflict  = errors.New("translation: persisted range conflicts with live route")
)

type Allocation struct {
	IPv4 netip.Prefix
	IPv6 netip.Prefix
}

// Probe returns routes currently installed on the host.
type Probe interface {
	Routes() ([]netip.Prefix, error)
}

// Backend atomically installs policy routing and reversible translation for
// one interface. Remove must be idempotent.
type Backend interface {
	Probe
	Install(interfaceName string, allocation Allocation) error
	Remove(interfaceName string, allocation Allocation) error
}

// Allocator serializes allocation so concurrent joins cannot claim one slot.
type Allocator struct {
	mu      sync.Mutex
	claimed map[string]Allocation
	probe   Probe
}

func NewAllocator(probe Probe) (*Allocator, error) {
	if probe == nil {
		return nil, errors.New("translation: route probe required")
	}
	return &Allocator{claimed: make(map[string]Allocation), probe: probe}, nil
}

// InterfaceName returns a stable Linux-safe interface name derived from
// membership identity. Linear probing resolves the unlikely truncated-hash
// collision without renaming existing interfaces.
func InterfaceName(membershipID string, claimed map[string]string) (string, error) {
	if membershipID == "" {
		return "", errors.New("translation: membership ID required")
	}
	sum := sha256.Sum256([]byte(membershipID))
	start := binary.BigEndian.Uint32(sum[:4])
	for step := uint32(0); ; step++ {
		name := fmt.Sprintf("hub%08x", start+step)
		owner, used := claimed[name]
		if !used || owner == membershipID {
			return name, nil
		}
		if step == ^uint32(0) {
			return "", ErrExhausted
		}
	}
}

// Allocate reuses a complete persisted pair only when both ranges remain
// conflict-free. New allocations start at a membership-derived slot and
// linearly probe, giving deterministic results for identical host state.
func (a *Allocator) Allocate(membershipID, persistedIPv4, persistedIPv6 string) (Allocation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if membershipID == "" {
		return Allocation{}, errors.New("translation: membership ID required")
	}
	routes, err := a.probe.Routes()
	if err != nil {
		return Allocation{}, fmt.Errorf("translation: probe routes: %w", err)
	}
	if persistedIPv4 != "" || persistedIPv6 != "" {
		if persistedIPv4 == "" || persistedIPv6 == "" {
			return Allocation{}, errors.New("translation: incomplete persisted allocation")
		}
		allocation, err := parseAllocation(persistedIPv4, persistedIPv6)
		if err != nil {
			return Allocation{}, err
		}
		if conflict(allocation, routes, a.claimed, membershipID) {
			return Allocation{}, ErrConflict
		}
		a.claimed[membershipID] = allocation
		return allocation, nil
	}

	v4Slots := prefixSlots(IPv4Pool, CanonicalIPv4.Bits())
	v6Slots := prefixSlots(IPv6Pool, CanonicalIPv6.Bits())
	if len(v4Slots) == 0 || len(v6Slots) == 0 {
		return Allocation{}, ErrExhausted
	}
	sum := sha256.Sum256([]byte(membershipID))
	start4 := int(binary.BigEndian.Uint64(sum[:8]) % uint64(len(v4Slots)))
	start6 := int(binary.BigEndian.Uint64(sum[8:16]) % uint64(len(v6Slots)))
	// Pair probes advance together. IPv4 is intentionally limiting; this
	// bounds the maximum concurrent sessions instead of reusing a route.
	for step := 0; step < len(v4Slots); step++ {
		candidate := Allocation{
			IPv4: v4Slots[(start4+step)%len(v4Slots)],
			IPv6: v6Slots[(start6+step)%len(v6Slots)],
		}
		if !conflict(candidate, routes, a.claimed, "") {
			a.claimed[membershipID] = candidate
			return candidate, nil
		}
	}
	return Allocation{}, ErrExhausted
}

func (a *Allocator) Release(membershipID string) {
	a.mu.Lock()
	delete(a.claimed, membershipID)
	a.mu.Unlock()
}

// TranslateDestination preserves host bits while mapping a translated local
// address to its signed canonical address.
func TranslateDestination(address netip.Addr, translated, canonical netip.Prefix) (netip.Addr, error) {
	if !translated.Contains(address) || translated.Bits() != canonical.Bits() ||
		translated.Addr().BitLen() != canonical.Addr().BitLen() {
		return netip.Addr{}, errors.New("translation: address outside compatible translated prefix")
	}
	return replacePrefix(address, translated.Bits(), canonical.Addr()), nil
}

// TranslateSource performs reverse translation for inbound canonical sources.
func TranslateSource(address netip.Addr, canonical, translated netip.Prefix) (netip.Addr, error) {
	return TranslateDestination(address, canonical, translated)
}

func parseAllocation(ipv4, ipv6 string) (Allocation, error) {
	v4, err := netip.ParsePrefix(ipv4)
	if err != nil || v4 != v4.Masked() || v4.Bits() != CanonicalIPv4.Bits() || !IPv4Pool.Contains(v4.Addr()) {
		return Allocation{}, errors.New("translation: invalid persisted IPv4 range")
	}
	v6, err := netip.ParsePrefix(ipv6)
	if err != nil || v6 != v6.Masked() || v6.Bits() != CanonicalIPv6.Bits() || !IPv6Pool.Contains(v6.Addr()) {
		return Allocation{}, errors.New("translation: invalid persisted IPv6 range")
	}
	return Allocation{IPv4: v4, IPv6: v6}, nil
}

func conflict(candidate Allocation, routes []netip.Prefix, claimed map[string]Allocation, owner string) bool {
	for _, route := range routes {
		if candidate.IPv4.Overlaps(route) || candidate.IPv6.Overlaps(route) {
			return true
		}
	}
	for id, allocation := range claimed {
		if id != owner && (candidate.IPv4.Overlaps(allocation.IPv4) || candidate.IPv6.Overlaps(allocation.IPv6)) {
			return true
		}
	}
	return false
}

func prefixSlots(pool netip.Prefix, bits int) []netip.Prefix {
	if bits < pool.Bits() || bits > pool.Addr().BitLen() {
		return nil
	}
	count := 1 << min(bits-pool.Bits(), 20)
	result := make([]netip.Prefix, 0, count)
	current := pool.Masked().Addr()
	stepBits := current.BitLen() - bits
	for i := 0; i < count; i++ {
		result = append(result, netip.PrefixFrom(current, bits))
		current = addPower(current, stepBits)
	}
	return result
}

func addPower(address netip.Addr, bit int) netip.Addr {
	bytes := address.As16()
	index := 15 - bit/8
	carry := uint16(1 << (bit % 8))
	for index >= 0 && carry != 0 {
		value := uint16(bytes[index]) + carry
		bytes[index] = byte(value)
		carry = value >> 8
		index--
	}
	if address.Is4() {
		var v4 [4]byte
		copy(v4[:], bytes[12:])
		return netip.AddrFrom4(v4)
	}
	return netip.AddrFrom16(bytes)
}

func replacePrefix(address netip.Addr, bits int, base netip.Addr) netip.Addr {
	source := address.As16()
	target := base.As16()
	offset := 0
	if address.Is4() {
		offset = 12
	}
	full := bits / 8
	partial := bits % 8
	copy(source[offset:offset+full], target[offset:offset+full])
	if partial != 0 {
		mask := byte(0xff << (8 - partial))
		source[offset+full] = target[offset+full]&mask | source[offset+full]&^mask
	}
	if address.Is4() {
		var v4 [4]byte
		copy(v4[:], source[12:])
		return netip.AddrFrom4(v4)
	}
	return netip.AddrFrom16(source)
}

// Sorted returns stable allocation strings for persistence and diagnostics.
func (a Allocation) Sorted() []string {
	values := []string{a.IPv4.String(), a.IPv6.String()}
	sort.Strings(values)
	return values
}
