//go:build windows

package enforcement

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func requireSixtyFourBit(t *testing.T) {
	t.Helper()
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the WFP layouts are the 64-bit ones")
	}
}

// Sizes and offsets are the 64-bit ones the Windows SDK headers give, as
// wireguard-windows tunnel/firewall types_windows_64.go records them.
func TestWFPStructLayouts(t *testing.T) {
	requireSixtyFourBit(t)
	var filter fwpmFilter0
	var condition fwpmFilterCondition0
	var session fwpmSession0
	var sublayer fwpmSublayer0
	var provider fwpmProvider0
	var value fwpValue0
	var action fwpmAction0
	var blob fwpByteBlob
	var display fwpmDisplayData0
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"FWPM_FILTER0 size", unsafe.Sizeof(filter), 200},
		{"FWPM_FILTER0.displayData", unsafe.Offsetof(filter.displayData), 16},
		{"FWPM_FILTER0.flags", unsafe.Offsetof(filter.flags), 32},
		{"FWPM_FILTER0.providerKey", unsafe.Offsetof(filter.providerKey), 40},
		{"FWPM_FILTER0.providerData", unsafe.Offsetof(filter.providerData), 48},
		{"FWPM_FILTER0.layerKey", unsafe.Offsetof(filter.layerKey), 64},
		{"FWPM_FILTER0.subLayerKey", unsafe.Offsetof(filter.subLayerKey), 80},
		{"FWPM_FILTER0.weight", unsafe.Offsetof(filter.weight), 96},
		{"FWPM_FILTER0.numFilterConditions", unsafe.Offsetof(filter.numFilterConditions), 112},
		{"FWPM_FILTER0.filterCondition", unsafe.Offsetof(filter.filterCondition), 120},
		{"FWPM_FILTER0.action", unsafe.Offsetof(filter.action), 128},
		{"FWPM_FILTER0.providerContextKey", unsafe.Offsetof(filter.providerContextKey), 152},
		{"FWPM_FILTER0.reserved", unsafe.Offsetof(filter.reserved), 168},
		{"FWPM_FILTER0.filterID", unsafe.Offsetof(filter.filterID), 176},
		{"FWPM_FILTER0.effectiveWeight", unsafe.Offsetof(filter.effectiveWeight), 184},
		{"FWPM_FILTER_CONDITION0 size", unsafe.Sizeof(condition), 40},
		{"FWPM_FILTER_CONDITION0.matchType", unsafe.Offsetof(condition.matchType), 16},
		{"FWPM_FILTER_CONDITION0.conditionValue", unsafe.Offsetof(condition.conditionValue), 24},
		{"FWPM_SESSION0 size", unsafe.Sizeof(session), 72},
		{"FWPM_SESSION0.displayData", unsafe.Offsetof(session.displayData), 16},
		{"FWPM_SESSION0.flags", unsafe.Offsetof(session.flags), 32},
		{"FWPM_SESSION0.txnWaitTimeoutInMSec", unsafe.Offsetof(session.txnWaitTimeoutInMSec), 36},
		{"FWPM_SESSION0.processId", unsafe.Offsetof(session.processID), 40},
		{"FWPM_SESSION0.sid", unsafe.Offsetof(session.sid), 48},
		{"FWPM_SESSION0.username", unsafe.Offsetof(session.username), 56},
		{"FWPM_SESSION0.kernelMode", unsafe.Offsetof(session.kernelMode), 64},
		{"FWPM_SUBLAYER0 size", unsafe.Sizeof(sublayer), 72},
		{"FWPM_SUBLAYER0.displayData", unsafe.Offsetof(sublayer.displayData), 16},
		{"FWPM_SUBLAYER0.flags", unsafe.Offsetof(sublayer.flags), 32},
		{"FWPM_SUBLAYER0.providerKey", unsafe.Offsetof(sublayer.providerKey), 40},
		{"FWPM_SUBLAYER0.providerData", unsafe.Offsetof(sublayer.providerData), 48},
		{"FWPM_SUBLAYER0.weight", unsafe.Offsetof(sublayer.weight), 64},
		{"FWPM_PROVIDER0 size", unsafe.Sizeof(provider), 64},
		{"FWPM_PROVIDER0.displayData", unsafe.Offsetof(provider.displayData), 16},
		{"FWPM_PROVIDER0.flags", unsafe.Offsetof(provider.flags), 32},
		{"FWPM_PROVIDER0.providerData", unsafe.Offsetof(provider.providerData), 40},
		{"FWPM_PROVIDER0.serviceName", unsafe.Offsetof(provider.serviceName), 56},
		{"FWP_VALUE0 size", unsafe.Sizeof(value), 16},
		{"FWP_VALUE0.value", unsafe.Offsetof(value.value), 8},
		{"FWPM_ACTION0 size", unsafe.Sizeof(action), 20},
		{"FWPM_ACTION0.filterType", unsafe.Offsetof(action.filterType), 4},
		{"FWP_BYTE_BLOB size", unsafe.Sizeof(blob), 16},
		{"FWP_BYTE_BLOB.data", unsafe.Offsetof(blob.data), 8},
		{"FWPM_DISPLAY_DATA0 size", unsafe.Sizeof(display), 16},
		{"FWPM_DISPLAY_DATA0.description", unsafe.Offsetof(display.description), 8},
		{"FWP_V4_ADDR_AND_MASK size", unsafe.Sizeof(fwpV4AddrAndMask{}), 8},
		{"FWP_V6_ADDR_AND_MASK size", unsafe.Sizeof(fwpV6AddrAndMask{}), 17},
		{"FWP_BYTE_ARRAY16 size", unsafe.Sizeof(fwpByteArray16{}), 16},
		{"MIB_TCPROW size", unsafe.Sizeof(mibTCPRow{}), 20},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %d, want %d", check.name, check.got, check.want)
		}
	}
}

// valuePointer reads a pointer-holding FWP_VALUE0 union. The arena keeps the
// target alive and on the heap, so reinterpreting the bits is safe here.
func valuePointer(value *fwpValue0) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&value.value))
}

func testRules() []Rule {
	expires := time.Now().Add(time.Minute)
	return []Rule{
		{
			ResourceID: "link:tcp", Source: netip.MustParseAddr("100.96.0.3"),
			Destination: netip.MustParseAddr("100.96.0.2"), DestinationPort: 9001, Protocol: "tcp", ExpiresAt: expires,
		},
		{
			ResourceID: "link:udp", Source: netip.MustParseAddr("fd48:5542:4e45::3"),
			Destination: netip.MustParseAddr("fd48:5542:4e45::2"), DestinationPort: 5353, Protocol: "udp", ExpiresAt: expires,
		},
		{
			ResourceID: controlResource, Destination: netip.MustParseAddr("100.96.0.2"),
			DestinationPort: 4433, Protocol: "tcp", ExpiresAt: expires,
		},
	}
}

func conditionsFor(spec filterSpec, field windows.GUID) []filterCondition {
	var matched []filterCondition
	for _, condition := range spec.conditions {
		if condition.field == field {
			matched = append(matched, condition)
		}
	}
	return matched
}

func TestFilterSpecsAllowExactTuplesThenBlockOverlay(t *testing.T) {
	const luid = 0x0123456789abcdef
	specs, err := buildFilterSpecs("hubnet0", luid, testRules())
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 5 {
		t.Fatalf("%d filters, want 3 permits and 2 blocks", len(specs))
	}
	for index, spec := range specs {
		wantPermit := index < 3
		if spec.permit != wantPermit {
			t.Fatalf("filter %d (%s) permit = %v", index, spec.name, spec.permit)
		}
		if wantPermit && spec.weight <= blockFilterWeight {
			t.Fatalf("permit %s weight %d not above block weight %d", spec.name, spec.weight, blockFilterWeight)
		}
		iface := conditionsFor(spec, fwpmConditionIPLocalInterface)
		if len(iface) != 1 || iface[0].kind != fwpUint64 || iface[0].number != luid {
			t.Fatalf("%s interface condition = %+v", spec.name, iface)
		}
	}

	byResource := map[string]filterSpec{}
	for _, spec := range specs[:3] {
		for _, rule := range testRules() {
			if conditionsFor(spec, fwpmConditionIPLocalPort)[0].number == uint64(rule.DestinationPort) {
				byResource[rule.ResourceID] = spec
			}
		}
	}

	tcp := byResource["link:tcp"]
	if tcp.ipv6 {
		t.Fatal("IPv4 rule on the IPv6 layer")
	}
	if got := conditionsFor(tcp, fwpmConditionIPLocalAddress); len(got) != 1 || got[0].kind != fwpUint32 || got[0].number != 0x64600002 {
		t.Fatalf("tcp local address = %+v, want UINT32 0x64600002", got)
	}
	if got := conditionsFor(tcp, fwpmConditionIPRemoteAddress); len(got) != 1 || got[0].kind != fwpUint32 || got[0].number != 0x64600003 {
		t.Fatalf("tcp remote address = %+v, want UINT32 0x64600003", got)
	}
	if got := conditionsFor(tcp, fwpmConditionIPProtocol); len(got) != 1 || got[0].kind != fwpUint8 || got[0].number != 6 {
		t.Fatalf("tcp protocol = %+v", got)
	}
	if got := conditionsFor(tcp, fwpmConditionIPLocalPort); len(got) != 1 || got[0].kind != fwpUint16 || got[0].number != 9001 {
		t.Fatalf("tcp port = %+v", got)
	}

	udp := byResource["link:udp"]
	if !udp.ipv6 {
		t.Fatal("IPv6 rule on the IPv4 layer")
	}
	remote := conditionsFor(udp, fwpmConditionIPRemoteAddress)
	if len(remote) != 1 || remote[0].kind != fwpByteArray16Type || remote[0].bytes != netip.MustParseAddr("fd48:5542:4e45::3").As16() {
		t.Fatalf("udp remote address = %+v", remote)
	}
	if got := conditionsFor(udp, fwpmConditionIPProtocol); len(got) != 1 || got[0].number != 17 {
		t.Fatalf("udp protocol = %+v", got)
	}

	control := byResource[controlResource]
	if got := conditionsFor(control, fwpmConditionIPRemoteAddress); len(got) != 0 {
		t.Fatalf("control rule without a source matches remote %+v", got)
	}

	block4, block6 := specs[3], specs[4]
	if block4.ipv6 || !block6.ipv6 {
		t.Fatal("blocks on the wrong layers")
	}
	if got := conditionsFor(block4, fwpmConditionIPProtocol); len(got) != 2 || got[0].number != 6 || got[1].number != 17 {
		t.Fatalf("block protocols = %+v", got)
	}
	if got := conditionsFor(block4, fwpmConditionIPLocalAddress); len(got) != 1 || got[0].kind != fwpV4AddrMask ||
		got[0].number != 0x64600000 || got[0].prefixLength != 11 {
		t.Fatalf("IPv4 block prefix = %+v", got)
	}
	if got := conditionsFor(block6, fwpmConditionIPLocalAddress); len(got) != 1 || got[0].kind != fwpV6AddrMask ||
		got[0].bytes != netip.MustParseAddr("fd48:5542:4e45::").As16() || got[0].prefixLength != 48 {
		t.Fatalf("IPv6 block prefix = %+v", got)
	}
}

func TestFilterSpecsWithoutRulesStillBlock(t *testing.T) {
	specs, err := buildFilterSpecs("hubnet0", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 || specs[0].permit || specs[1].permit {
		t.Fatalf("specs = %+v, want the two overlay blocks", specs)
	}
}

func TestFilterSpecsRejectInvalidRules(t *testing.T) {
	for name, rule := range map[string]Rule{
		"protocol": {Source: netip.MustParseAddr("100.96.0.3"), Destination: netip.MustParseAddr("100.96.0.2"), DestinationPort: 1, Protocol: "icmp"},
		"family":   {Source: netip.MustParseAddr("fd48:5542:4e45::3"), Destination: netip.MustParseAddr("100.96.0.2"), DestinationPort: 1, Protocol: "tcp"},
		"address":  {DestinationPort: 1, Protocol: "tcp"},
	} {
		if _, err := buildFilterSpecs("hubnet0", 1, []Rule{rule}); !errors.Is(err, ErrInvalidAuthorization) {
			t.Errorf("%s: error = %v, want ErrInvalidAuthorization", name, err)
		}
	}
}

func TestMarshalFilterEncodesConditionValues(t *testing.T) {
	requireSixtyFourBit(t)
	const luid = 0x0001000200030004
	specs, err := buildFilterSpecs("hubnet0", luid, testRules()[:1])
	if err != nil {
		t.Fatal(err)
	}
	var arena wfpArena
	permit, err := arena.marshal(specs[0])
	if err != nil {
		t.Fatal(err)
	}
	if permit.layerKey != fwpmLayerALEAuthRecvAcceptV4 || permit.subLayerKey != hubNetSublayerKey ||
		permit.providerKey == nil || *permit.providerKey != hubNetProviderKey {
		t.Fatal("permit not in hub-net's sublayer at ALE_AUTH_RECV_ACCEPT_V4")
	}
	if permit.action.typ != fwpActionPermit || permit.flags != fwpmFilterClearAR {
		t.Fatalf("permit action 0x%x flags 0x%x, want a hard permit", permit.action.typ, permit.flags)
	}
	if permit.weight.typ != fwpUint8 || permit.weight.value != uintptr(permitFilterWeight) {
		t.Fatalf("permit weight = %+v", permit.weight)
	}
	conditions := unsafe.Slice(permit.filterCondition, permit.numFilterConditions)
	if len(conditions) != 5 {
		t.Fatalf("%d permit conditions, want 5", len(conditions))
	}
	for _, condition := range conditions {
		value := condition.conditionValue
		if condition.matchType != fwpMatchEqual {
			t.Fatalf("match type %d", condition.matchType)
		}
		switch condition.fieldKey {
		case fwpmConditionIPLocalInterface:
			if value.typ != fwpUint64 || *(*uint64)(valuePointer(&value)) != luid {
				t.Fatalf("interface value = %+v", value)
			}
		case fwpmConditionIPLocalPort:
			if value.typ != fwpUint16 || value.value != 9001 {
				t.Fatalf("port value = %+v", value)
			}
		case fwpmConditionIPLocalAddress:
			if value.typ != fwpUint32 || value.value != 0x64600002 {
				t.Fatalf("local address value = %+v", value)
			}
		}
	}

	block6, err := arena.marshal(specs[2])
	if err != nil {
		t.Fatal(err)
	}
	if block6.layerKey != fwpmLayerALEAuthRecvAcceptV6 || block6.action.typ != fwpActionBlock || block6.flags != fwpmFilterClearAR {
		t.Fatal("IPv6 block not a hard block at ALE_AUTH_RECV_ACCEPT_V6")
	}
	block4, err := arena.marshal(specs[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range unsafe.Slice(block4.filterCondition, block4.numFilterConditions) {
		if condition.fieldKey == fwpmConditionIPLocalAddress {
			mask := *(*fwpV4AddrAndMask)(valuePointer(&condition.conditionValue))
			if condition.conditionValue.typ != fwpV4AddrMask || mask.addr != 0x64600000 || mask.mask != 0xffe00000 {
				t.Fatalf("IPv4 block mask = %+v", mask)
			}
		}
	}
	for _, condition := range unsafe.Slice(block6.filterCondition, block6.numFilterConditions) {
		if condition.fieldKey == fwpmConditionIPLocalAddress {
			mask := *(*fwpV6AddrAndMask)(valuePointer(&condition.conditionValue))
			if condition.conditionValue.typ != fwpV6AddrMask || mask.prefixLength != 48 || mask.addr[0] != 0xfd || mask.addr[5] != 0x45 {
				t.Fatalf("IPv6 block mask = %+v", mask)
			}
		}
	}
}

// tcpRow builds a MIB_TCPROW the way GetTcpTable fills it.
func tcpRow(state uint32, local netip.AddrPort, remote netip.Addr) mibTCPRow {
	addr := func(address netip.Addr) uint32 {
		bytes := address.As4()
		return binary.LittleEndian.Uint32(bytes[:])
	}
	port := func(value uint16) uint32 {
		var bytes [4]byte
		binary.BigEndian.PutUint16(bytes[:2], value)
		return binary.LittleEndian.Uint32(bytes[:])
	}
	return mibTCPRow{state: state, localAddr: addr(local.Addr()), localPort: port(local.Port()), remoteAddr: addr(remote), remotePort: port(50000)}
}

func TestTCPRowsMatchingRemovedRule(t *testing.T) {
	local := netip.MustParseAddrPort("100.96.0.2:9001")
	peer := netip.MustParseAddr("100.96.0.3")
	other := netip.MustParseAddr("100.96.0.4")
	rows := []mibTCPRow{
		tcpRow(5, local, peer),  // established from the rule's source
		tcpRow(5, local, other), // another peer
		tcpRow(mibTCPStateListen, local, netip.IPv4Unspecified()),
		tcpRow(5, netip.MustParseAddrPort("100.96.0.2:9002"), peer),
	}
	if rows[0].local() != local || rows[0].remote() != peer {
		t.Fatalf("row decodes as %s <- %s", rows[0].local(), rows[0].remote())
	}
	rule := testRules()[0]
	if got := tcpRowsMatching(rows, rule); len(got) != 1 || got[0] != rows[0] {
		t.Fatalf("matched %+v, want only the source's connection", got)
	}
	anySource := rule
	anySource.Source = netip.Addr{}
	if got := tcpRowsMatching(rows, anySource); len(got) != 2 {
		t.Fatalf("matched %d rows for a rule with no source, want both connections", len(got))
	}
	udp := rule
	udp.Protocol = "udp"
	if got := tcpRowsMatching(rows, udp); len(got) != 0 {
		t.Fatalf("UDP rule matched TCP rows %+v", got)
	}
}

func TestWindowsPlatformSupported(t *testing.T) {
	requireSixtyFourBit(t)
	if err := PlatformSupported(); err != nil {
		t.Fatalf("PlatformSupported: %v", err)
	}
	if backend, err := NewPlatformBackend(""); backend != nil || !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("backend = %T, error = %v", backend, err)
	}
}

// Without the adapter nothing is installed and the error says so.
func TestReplaceRulesNeedsTheInterface(t *testing.T) {
	requireSixtyFourBit(t)
	backend, err := NewPlatformBackend("hubnet-test-missing-adapter")
	if err != nil {
		t.Fatal(err)
	}
	windowsBackend := backend.(*windowsBackend)
	if err := backend.ReplaceRules(nil); !errors.Is(err, errInterfaceNotFound) {
		t.Fatalf("ReplaceRules = %v, want interface not found", err)
	}
	if windowsBackend.acquired || len(windowsBackend.filterIDs) != 0 {
		t.Fatal("filters installed without the interface")
	}
	if err := windowsBackend.Close(); err != nil {
		t.Fatal(err)
	}
	if err := backend.ReplaceRules(nil); !errors.Is(err, errBackendClosed) {
		t.Fatalf("ReplaceRules after Close = %v", err)
	}
}

// openQueryEngine opens a separate, non-dynamic WFP session that only reads.
func openQueryEngine(t *testing.T) uintptr {
	t.Helper()
	var arena wfpArena
	session := arenaNew(&arena, fwpmSession0{txnWaitTimeoutInMSec: wfpTxnWaitTimeoutMs})
	var handle uintptr
	if err := fwpmEngineOpen0(session, &handle); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fwpmEngineClose0(handle) })
	return handle
}

// lookupFilter returns whether id exists and, if so, its action type.
func lookupFilter(t *testing.T, handle uintptr, id uint64) (bool, uint32) {
	t.Helper()
	filter, err := fwpmFilterGetByID0(handle, id)
	if isWFPCode(err, fwpEFilterNotFound) {
		return false, 0
	}
	if err != nil {
		t.Fatalf("get filter %d: %v", id, err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&filter))
	if filter.providerKey == nil || *filter.providerKey != hubNetProviderKey || filter.subLayerKey != hubNetSublayerKey {
		t.Fatalf("filter %d is not in hub-net's sublayer", id)
	}
	if filter.flags&fwpmFilterClearAR == 0 {
		t.Fatalf("filter %d lacks FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT", id)
	}
	return true, filter.action.typ
}

// TestWindowsBackendPrivilegedLifecycle installs real WFP filters. Run it
// elevated with HUBNET_WFP_TEST=1 and HUBNET_WFP_IFACE naming an existing
// adapter (a WireGuardNT tunnel, say). The filters it adds are dynamic and
// go away with the test process even if it fails midway.
func TestWindowsBackendPrivilegedLifecycle(t *testing.T) {
	requireSixtyFourBit(t)
	if os.Getenv("HUBNET_WFP_TEST") != "1" {
		t.Skip("set HUBNET_WFP_TEST=1 (and HUBNET_WFP_IFACE) to install real WFP filters")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated process")
	}
	iface := os.Getenv("HUBNET_WFP_IFACE")
	if iface == "" {
		t.Skip("set HUBNET_WFP_IFACE to an existing adapter's alias")
	}
	query := openQueryEngine(t)

	backend, err := NewPlatformBackend(iface)
	if err != nil {
		t.Fatalf("NewPlatformBackend: %v", err)
	}
	windowsBackend := backend.(*windowsBackend)
	t.Cleanup(func() { _ = windowsBackend.Close() })

	if err := backend.ReplaceRules(testRules()); err != nil {
		t.Fatalf("ReplaceRules: %v", err)
	}
	first := append([]uint64(nil), windowsBackend.filterIDs...)
	if len(first) != 5 {
		t.Fatalf("%d filters, want 5", len(first))
	}
	permits, blocks := 0, 0
	for _, id := range first {
		exists, action := lookupFilter(t, query, id)
		if !exists {
			t.Fatalf("filter %d missing after ReplaceRules", id)
		}
		switch action {
		case fwpActionPermit:
			permits++
		case fwpActionBlock:
			blocks++
		}
	}
	if permits != 3 || blocks != 2 {
		t.Fatalf("%d permits and %d blocks, want 3 and 2", permits, blocks)
	}

	if err := backend.ReplaceRules(nil); err != nil {
		t.Fatalf("clear rules: %v", err)
	}
	for _, id := range first {
		if exists, _ := lookupFilter(t, query, id); exists {
			t.Fatalf("filter %d from the previous set survived the replacement", id)
		}
	}
	second := append([]uint64(nil), windowsBackend.filterIDs...)
	if len(second) != 2 {
		t.Fatalf("%d filters with no rules, want the 2 blocks", len(second))
	}
	for _, id := range second {
		if exists, action := lookupFilter(t, query, id); !exists || action != fwpActionBlock {
			t.Fatalf("block %d missing with no rules", id)
		}
	}
	if err := backend.TerminateResource("link:tcp"); err != nil {
		t.Fatalf("TerminateResource: %v", err)
	}

	if err := windowsBackend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, id := range second {
		if exists, _ := lookupFilter(t, query, id); exists {
			t.Fatalf("filter %d survived Close", id)
		}
	}
	if sharedWFPEngine.refs != 0 {
		t.Fatalf("WFP session still held by %d backends", sharedWFPEngine.refs)
	}
}
