//go:build windows

package enforcement

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The overlay prefixes whose inbound TCP and UDP the backend drops unless a
// rule allows it (the same ones the Linux nftables backend drops).
var (
	overlayPrefixV4 = netip.MustParsePrefix("100.96.0.0/11")
	overlayPrefixV6 = netip.MustParsePrefix("fd48:5542:4e45::/48")
)

// Filter weights inside hub-net's sublayer (FWP_UINT8, 0 to 15): a rule's
// permit is evaluated before the overlay block.
const (
	blockFilterWeight  uint8 = 1
	permitFilterWeight uint8 = 10
)

var errBackendClosed = errors.New("enforcement: firewall backend closed")

// windowsBackend enforces the rules with the Windows Filtering Platform, at
// the ALE receive/accept layers (the first inbound packet of a TCP
// connection or UDP flow), for traffic whose local interface is the overlay
// adapter:
//
//   - one permit filter per rule: remote address == Source (any when the
//     rule has none), local address == Destination, protocol, local port;
//   - one block filter per family for every other inbound TCP and UDP to an
//     overlay address.
//
// Both carry FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT in a sublayer weighted
// above Windows Defender Firewall's, so a permit is not overridden by
// Defender's default inbound block and the block is not overridden by a
// Defender allow rule: the Hub decides. Replies to connections this host
// opened belong to outbound ALE flows, authorized at ALE_AUTH_CONNECT, and
// never reach these filters (the Linux backend's "ct state established").
//
// Each ReplaceRules swaps every filter in one WFP transaction. The session is
// dynamic, so the filters go away with the process; Close removes them on a
// clean shutdown.
type windowsBackend struct {
	mu            sync.Mutex
	interfaceName string
	engine        *wfpEngine
	acquired      bool
	closed        bool
	filterIDs     []uint64
	rules         []Rule
	removed       map[string][]Rule
}

func newPlatformBackend(interfaceName string) (Backend, error) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		// The WFP struct layouts here are the 64-bit ones.
		return nil, ErrPlatformUnsupported
	}
	if err := modFwpuclnt.Load(); err != nil {
		return nil, fmt.Errorf("enforcement: Windows Filtering Platform unavailable: %w", err)
	}
	for _, proc := range append(append([]*windows.LazyProc(nil), wfpProcs...), iphlpProcs...) {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("enforcement: Windows Filtering Platform unavailable: %w", err)
		}
	}
	if err := baseFilteringEngineRunning(); err != nil {
		return nil, fmt.Errorf("enforcement: Windows Filtering Platform unavailable: %w", err)
	}
	return &windowsBackend{
		interfaceName: interfaceName,
		engine:        &sharedWFPEngine,
		removed:       make(map[string][]Rule),
	}, nil
}

// baseFilteringEngineRunning checks the BFE service, which owns every WFP
// object, without opening a WFP session (that needs no elevation: the
// hub-net CLI asks too).
func baseFilteringEngineRunning() error {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("open service manager: %w", err)
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString("BFE")
	if err != nil {
		return err
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return fmt.Errorf("open Base Filtering Engine service: %w", err)
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(service, &status); err != nil {
		return fmt.Errorf("query Base Filtering Engine service: %w", err)
	}
	if status.CurrentState != windows.SERVICE_RUNNING {
		return fmt.Errorf("Base Filtering Engine service is not running (state %d)", status.CurrentState)
	}
	return nil
}

// ReplaceRules installs exactly rules plus the overlay block, replacing the
// previous set atomically. The first call installs the block even with no
// rules. The overlay adapter must exist: its LUID is looked up on every call,
// so a recreated adapter gets the filters too.
func (b *windowsBackend) ReplaceRules(rules []Rule) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errBackendClosed
	}
	luid, err := interfaceLUID(b.interfaceName)
	if err != nil {
		return err
	}
	specs, err := buildFilterSpecs(b.interfaceName, luid, rules)
	if err != nil {
		return err
	}
	var arena wfpArena
	filters := make([]*fwpmFilter0, 0, len(specs))
	for _, spec := range specs {
		filter, err := arena.marshal(spec)
		if err != nil {
			return err
		}
		filters = append(filters, filter)
	}
	if !b.acquired {
		if err := b.engine.acquire(); err != nil {
			return err
		}
		b.acquired = true
	}
	ids := make([]uint64, 0, len(filters))
	err = b.engine.transact(func(handle uintptr) error {
		if err := deleteFilters(handle, b.filterIDs); err != nil {
			return err
		}
		for _, filter := range filters {
			var id uint64
			if err := fwpmFilterAdd0(handle, filter, &id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})
	runtime.KeepAlive(&arena)
	if err != nil {
		return fmt.Errorf("enforcement: install WFP filters on %s: %w", b.interfaceName, err)
	}
	b.filterIDs = ids

	nextKeys := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		nextKeys[ruleKey(rule)] = struct{}{}
	}
	for _, rule := range b.rules {
		if _, retained := nextKeys[ruleKey(rule)]; !retained {
			b.removed[rule.ResourceID] = append(b.removed[rule.ResourceID], rule)
		}
	}
	b.rules = append([]Rule(nil), rules...)
	return nil
}

func deleteFilters(handle uintptr, ids []uint64) error {
	for _, id := range ids {
		if err := fwpmFilterDeleteByID0(handle, id); err != nil && !isWFPCode(err, fwpEFilterNotFound) {
			return err
		}
	}
	return nil
}

// TerminateResource ends the flows of resourceID's rules that the last
// ReplaceRules removed. Removing a permit already stops them: a filter change
// at the ALE receive/accept layer makes WFP reauthorize every inbound ALE
// flow on its next packet, and the flow then meets the overlay block. That
// covers TCP and UDP, IPv4 and IPv6. IPv4 TCP connections are also reset
// here (SetTcpEntry, MIB_TCP_STATE_DELETE_TCB), so the local socket and the
// peer learn at once instead of on their next packet or a timeout. Windows
// has no such call for IPv6 TCP, and UDP has no connection to reset.
func (b *windowsBackend) TerminateResource(resourceID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	rules := b.removed[resourceID]
	delete(b.removed, resourceID)
	needTable := false
	for _, rule := range rules {
		if rule.Protocol == "tcp" && rule.Destination.Unmap().Is4() {
			needTable = true
		}
	}
	if !needTable {
		return nil
	}
	rows, err := tcpTable()
	if err != nil {
		return fmt.Errorf("enforcement: list TCP connections: %w", err)
	}
	var errs []error
	for _, rule := range rules {
		for _, row := range tcpRowsMatching(rows, rule) {
			if b.stillAllowedLocked(row) {
				continue
			}
			if err := resetTCPConnection(row); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("enforcement: reset TCP connections: %w", err)
	}
	return nil
}

// stillAllowedLocked reports whether a current rule (another resource's,
// say) still lets the connection in.
func (b *windowsBackend) stillAllowedLocked(row mibTCPRow) bool {
	for _, rule := range b.rules {
		if len(tcpRowsMatching([]mibTCPRow{row}, rule)) > 0 {
			return true
		}
	}
	return false
}

// Close deletes this backend's filters and drops its hold on the WFP
// session; the last backend in the process closes the session, removing
// hub-net's provider and sublayer. Afterwards the overlay ports are no
// longer limited. Call it on clean shutdown and on failed startup; a crashed
// process is covered by the dynamic session. It is safe to call twice.
func (b *windowsBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	if !b.acquired {
		return nil
	}
	ids := b.filterIDs
	b.filterIDs = nil
	b.rules = nil
	b.removed = map[string][]Rule{}
	var errs []error
	if err := b.engine.transact(func(handle uintptr) error { return deleteFilters(handle, ids) }); err != nil {
		errs = append(errs, fmt.Errorf("enforcement: delete WFP filters: %w", err))
	}
	b.acquired = false
	if err := b.engine.release(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// filterCondition is one FWPM_FILTER_CONDITION0 before marshalling. kind is
// the FWP data type; number holds UINT8..UINT64 values and IPv4 addresses
// (host byte order), bytes IPv6 addresses.
type filterCondition struct {
	field        windows.GUID
	kind         uint32
	number       uint64
	bytes        [16]byte
	prefixLength uint8
}

// filterSpec is one WFP filter in hub-net's sublayer before marshalling.
type filterSpec struct {
	name       string
	ipv6       bool
	permit     bool
	weight     uint8
	conditions []filterCondition
}

func interfaceCondition(luid uint64) filterCondition {
	return filterCondition{field: fwpmConditionIPLocalInterface, kind: fwpUint64, number: luid}
}

func protocolCondition(protocol uint8) filterCondition {
	return filterCondition{field: fwpmConditionIPProtocol, kind: fwpUint8, number: uint64(protocol)}
}

// addressCondition matches exactly address: FWP_UINT32 in host byte order
// for IPv4, FWP_BYTE_ARRAY16 in network byte order for IPv6.
func addressCondition(field windows.GUID, address netip.Addr) filterCondition {
	address = address.Unmap()
	if address.Is4() {
		bytes := address.As4()
		return filterCondition{field: field, kind: fwpUint32, number: uint64(bytes[0])<<24 | uint64(bytes[1])<<16 | uint64(bytes[2])<<8 | uint64(bytes[3])}
	}
	return filterCondition{field: field, kind: fwpByteArray16Type, bytes: address.As16()}
}

// prefixCondition matches every address in prefix.
func prefixCondition(field windows.GUID, prefix netip.Prefix) filterCondition {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		condition := addressCondition(field, prefix.Addr())
		condition.kind = fwpV4AddrMask
		condition.prefixLength = uint8(prefix.Bits())
		return condition
	}
	return filterCondition{field: field, kind: fwpV6AddrMask, bytes: prefix.Addr().As16(), prefixLength: uint8(prefix.Bits())}
}

// buildFilterSpecs turns rules into the permits, sorted like the Linux
// ruleset, followed by the IPv4 and IPv6 overlay blocks.
func buildFilterSpecs(interfaceName string, luid uint64, rules []Rule) ([]filterSpec, error) {
	sorted := append([]Rule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return ruleKey(sorted[i]) < ruleKey(sorted[j]) })
	specs := make([]filterSpec, 0, len(sorted)+2)
	for _, rule := range sorted {
		destination := rule.Destination.Unmap()
		source := rule.Source.Unmap()
		var protocol uint8
		switch rule.Protocol {
		case "tcp":
			protocol = ipProtoTCP
		case "udp":
			protocol = ipProtoUDP
		default:
			return nil, fmt.Errorf("%w: protocol %q", ErrInvalidAuthorization, rule.Protocol)
		}
		if !destination.IsValid() || (source.IsValid() && source.Is4() != destination.Is4()) {
			return nil, fmt.Errorf("%w: %s -> %s", ErrInvalidAuthorization, rule.Source, rule.Destination)
		}
		conditions := []filterCondition{
			interfaceCondition(luid),
			addressCondition(fwpmConditionIPLocalAddress, destination),
			protocolCondition(protocol),
			{field: fwpmConditionIPLocalPort, kind: fwpUint16, number: uint64(rule.DestinationPort)},
		}
		from := "any"
		if source.IsValid() {
			conditions = append(conditions, addressCondition(fwpmConditionIPRemoteAddress, source))
			from = source.String()
		}
		specs = append(specs, filterSpec{
			name:   fmt.Sprintf("hub-net %s: allow %s %s -> %s port %d", interfaceName, rule.ResourceID, from, destination, rule.DestinationPort),
			ipv6:   destination.Is6(),
			permit: true, weight: permitFilterWeight, conditions: conditions,
		})
	}
	for _, prefix := range []netip.Prefix{overlayPrefixV4, overlayPrefixV6} {
		specs = append(specs, filterSpec{
			name:   fmt.Sprintf("hub-net %s: block other inbound TCP and UDP to %s", interfaceName, prefix),
			ipv6:   prefix.Addr().Is6(),
			weight: blockFilterWeight,
			conditions: []filterCondition{
				interfaceCondition(luid),
				// Conditions on the same field are ORed, different fields ANDed.
				protocolCondition(ipProtoTCP),
				protocolCondition(ipProtoUDP),
				prefixCondition(fwpmConditionIPLocalAddress, prefix),
			},
		})
	}
	return specs, nil
}

var (
	_ Backend                    = (*windowsBackend)(nil)
	_ interface{ Close() error } = (*windowsBackend)(nil)
)
