//go:build windows

package enforcement

// Windows Filtering Platform (WFP) management API: struct layouts, constants
// and fwpuclnt.dll calls. The layouts are adapted from wireguard-windows
// tunnel/firewall (MIT, Copyright (C) 2019-2026 WireGuard LLC) and are the
// 64-bit (amd64, arm64) ones; newPlatformBackend refuses 32-bit Windows.

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FWP_DATA_TYPE (fwptypes.h).
const (
	fwpEmpty            uint32 = 0
	fwpUint8            uint32 = 1
	fwpUint16           uint32 = 2
	fwpUint32           uint32 = 3
	fwpUint64           uint32 = 4
	fwpByteArray16Type  uint32 = 11
	fwpV4AddrMask       uint32 = 0x100
	fwpV6AddrMask       uint32 = 0x101
	fwpMatchEqual       uint32 = 0
	fwpActionBlock      uint32 = 0x00000001 | 0x00001000 // | FWP_ACTION_FLAG_TERMINATING
	fwpActionPermit     uint32 = 0x00000002 | 0x00001000
	fwpmSessionDynamic  uint32 = 0x00000001 // FWPM_SESSION_FLAG_DYNAMIC
	fwpmFilterClearAR   uint32 = 0x00000008 // FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
	rpcCAuthnWinNT      uint32 = 10         // RPC_C_AUTHN_WINNT
	ipProtoTCP          uint8  = 6
	ipProtoUDP          uint8  = 17
	wfpTxnWaitTimeoutMs uint32 = 10_000
)

// HRESULTs from fwpmu.h this package tells apart.
const (
	fwpEFilterNotFound uint32 = 0x80320003
	fwpEAlreadyExists  uint32 = 0x80320009
)

// Layer and condition keys (fwpmu.h).
var (
	// e1cd9fe7-f4b5-4273-96c0-592e487b8650
	fwpmLayerALEAuthRecvAcceptV4 = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	// a3b42c97-9f04-4672-b87e-cee9c483257f
	fwpmLayerALEAuthRecvAcceptV6 = windows.GUID{Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672, Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}
	// 4cd62a49-59c3-4969-b7f3-bda5d32890a4
	fwpmConditionIPLocalInterface = windows.GUID{Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969, Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	// b235ae9a-1d64-49b8-a44c-5ff3d9095045
	fwpmConditionIPRemoteAddress = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	// d9ee00de-c1ef-4617-bfe3-ffd8f5a08957
	fwpmConditionIPLocalAddress = windows.GUID{Data1: 0xd9ee00de, Data2: 0xc1ef, Data3: 0x4617, Data4: [8]byte{0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57}}
	// 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7
	fwpmConditionIPProtocol = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	// 0c1ba1af-5765-453f-af22-a8f791ac775b
	fwpmConditionIPLocalPort = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
)

// hub-net's own WFP objects. Fixed keys, so `netsh wfp show filters` and
// tests can tell them apart; they live only as long as the dynamic session.
var (
	// f11847ef-600e-4d0f-bf00-fb599f1b3bab
	hubNetProviderKey = windows.GUID{Data1: 0xf11847ef, Data2: 0x600e, Data3: 0x4d0f, Data4: [8]byte{0xbf, 0x00, 0xfb, 0x59, 0x9f, 0x1b, 0x3b, 0xab}}
	// 82906956-0bf7-4945-a44b-0e6b90cecf55
	hubNetSublayerKey = windows.GUID{Data1: 0x82906956, Data2: 0x0bf7, Data3: 0x4945, Data4: [8]byte{0xa4, 0x4b, 0x0e, 0x6b, 0x90, 0xce, 0xcf, 0x55}}
)

// hubNetSublayerWeight puts hub-net's sublayer first among the ALE
// sublayers, ahead of Windows Defender Firewall's, so its hard permits and
// blocks decide before Defender's default inbound block.
const hubNetSublayerWeight uint16 = 0xffff

// FWP_BYTE_BLOB
type fwpByteBlob struct {
	size uint32
	data *uint8
}

// FWPM_DISPLAY_DATA0
type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

// FWP_VALUE0 and FWP_CONDITION_VALUE0 (same layout): a type tag and a union
// that holds UINT8/16/32 inline and a pointer for everything else.
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

// FWP_V4_ADDR_AND_MASK, host byte order.
type fwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

// FWP_V6_ADDR_AND_MASK, network byte order.
type fwpV6AddrAndMask struct {
	addr         [16]uint8
	prefixLength uint8
}

// FWP_BYTE_ARRAY16
type fwpByteArray16 struct {
	byteArray16 [16]uint8
}

// FWPM_FILTER_CONDITION0
type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpValue0
}

// FWPM_ACTION0
type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

// FWPM_FILTER0 (64-bit layout).
type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_                   [4]byte // the C union with providerContextKey holds a UINT64, so it is 8-aligned
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

// FWPM_SESSION0
type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32 // BOOL
}

// FWPM_PROVIDER0
type fwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

// FWPM_SUBLAYER0
type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

var (
	modFwpuclnt                = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0        = modFwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0       = modFwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmProviderAdd0       = modFwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmSubLayerAdd0       = modFwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0         = modFwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteById0  = modFwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmFilterGetById0     = modFwpuclnt.NewProc("FwpmFilterGetById0")
	procFwpmFreeMemory0        = modFwpuclnt.NewProc("FwpmFreeMemory0")
	procFwpmTransactionBegin0  = modFwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0 = modFwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0  = modFwpuclnt.NewProc("FwpmTransactionAbort0")

	wfpProcs = []*windows.LazyProc{
		procFwpmEngineOpen0, procFwpmEngineClose0, procFwpmProviderAdd0, procFwpmSubLayerAdd0,
		procFwpmFilterAdd0, procFwpmFilterDeleteById0, procFwpmFilterGetById0, procFwpmFreeMemory0,
		procFwpmTransactionBegin0, procFwpmTransactionCommit0, procFwpmTransactionAbort0,
	}
)

// wfpError is a failed fwpuclnt call and the DWORD/HRESULT it returned.
type wfpError struct {
	op   string
	code uint32
}

func (e *wfpError) Error() string {
	return fmt.Sprintf("%s: 0x%08x (%v)", e.op, e.code, windows.Errno(e.code))
}

func isWFPCode(err error, code uint32) bool {
	var wfpErr *wfpError
	return errors.As(err, &wfpErr) && wfpErr.code == code
}

func wfpCall(op string, proc *windows.LazyProc, args ...uintptr) error {
	if err := proc.Find(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	r1, _, _ := proc.Call(args...)
	if r1 != 0 {
		return &wfpError{op: op, code: uint32(r1)}
	}
	return nil
}

func fwpmEngineOpen0(session *fwpmSession0, handle *uintptr) error {
	return wfpCall("FwpmEngineOpen0", procFwpmEngineOpen0, 0, uintptr(rpcCAuthnWinNT), 0,
		uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(handle)))
}

func fwpmEngineClose0(handle uintptr) error {
	return wfpCall("FwpmEngineClose0", procFwpmEngineClose0, handle)
}

func fwpmProviderAdd0(handle uintptr, provider *fwpmProvider0) error {
	return wfpCall("FwpmProviderAdd0", procFwpmProviderAdd0, handle, uintptr(unsafe.Pointer(provider)), 0)
}

func fwpmSubLayerAdd0(handle uintptr, sublayer *fwpmSublayer0) error {
	return wfpCall("FwpmSubLayerAdd0", procFwpmSubLayerAdd0, handle, uintptr(unsafe.Pointer(sublayer)), 0)
}

func fwpmFilterAdd0(handle uintptr, filter *fwpmFilter0, id *uint64) error {
	return wfpCall("FwpmFilterAdd0", procFwpmFilterAdd0, handle, uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(id)))
}

func fwpmFilterDeleteByID0(handle uintptr, id uint64) error {
	return wfpCall("FwpmFilterDeleteById0", procFwpmFilterDeleteById0, handle, uintptr(id))
}

// fwpmFilterGetByID0 returns the filter WFP allocated; release it with
// fwpmFreeMemory0.
func fwpmFilterGetByID0(handle uintptr, id uint64) (*fwpmFilter0, error) {
	var filter *fwpmFilter0
	err := wfpCall("FwpmFilterGetById0", procFwpmFilterGetById0, handle, uintptr(id), uintptr(unsafe.Pointer(&filter)))
	return filter, err
}

func fwpmFreeMemory0(pointer unsafe.Pointer) {
	if procFwpmFreeMemory0.Find() == nil {
		_, _, _ = procFwpmFreeMemory0.Call(uintptr(pointer))
	}
}

func fwpmTransactionBegin0(handle uintptr) error {
	return wfpCall("FwpmTransactionBegin0", procFwpmTransactionBegin0, handle, 0)
}

func fwpmTransactionCommit0(handle uintptr) error {
	return wfpCall("FwpmTransactionCommit0", procFwpmTransactionCommit0, handle)
}

func fwpmTransactionAbort0(handle uintptr) error {
	return wfpCall("FwpmTransactionAbort0", procFwpmTransactionAbort0, handle)
}

// wfpArena keeps everything a filter's FWP_VALUE0 unions point at. Those
// pointers are stored as uintptr, which neither the GC nor stack copying
// track, so their targets are allocated here, on the (non-moving) heap, and
// stay reachable until the arena is dropped after the WFP call.
type wfpArena struct {
	keep []any
}

func arenaNew[T any](arena *wfpArena, value T) *T {
	pointer := new(T)
	*pointer = value
	arena.keep = append(arena.keep, pointer)
	return pointer
}

func (a *wfpArena) utf16(value string) (*uint16, error) {
	pointer, err := windows.UTF16PtrFromString(value)
	if err != nil {
		return nil, err
	}
	a.keep = append(a.keep, pointer)
	return pointer, nil
}

func (a *wfpArena) displayData(name, description string) (fwpmDisplayData0, error) {
	namePointer, err := a.utf16(name)
	if err != nil {
		return fwpmDisplayData0{}, err
	}
	descriptionPointer, err := a.utf16(description)
	if err != nil {
		return fwpmDisplayData0{}, err
	}
	return fwpmDisplayData0{name: namePointer, description: descriptionPointer}, nil
}

// conditionValue encodes one condition value as FWP_CONDITION_VALUE0.
func (a *wfpArena) conditionValue(condition filterCondition) (fwpValue0, error) {
	switch condition.kind {
	case fwpUint8, fwpUint16, fwpUint32:
		return fwpValue0{typ: condition.kind, value: uintptr(condition.number)}, nil
	case fwpUint64:
		return fwpValue0{typ: fwpUint64, value: uintptr(unsafe.Pointer(arenaNew(a, condition.number)))}, nil
	case fwpByteArray16Type:
		return fwpValue0{typ: fwpByteArray16Type, value: uintptr(unsafe.Pointer(arenaNew(a, fwpByteArray16{condition.bytes})))}, nil
	case fwpV4AddrMask:
		mask := uint32(0)
		if condition.prefixLength > 0 {
			mask = ^uint32(0) << (32 - uint32(condition.prefixLength))
		}
		value := fwpV4AddrAndMask{addr: uint32(condition.number) & mask, mask: mask}
		return fwpValue0{typ: fwpV4AddrMask, value: uintptr(unsafe.Pointer(arenaNew(a, value)))}, nil
	case fwpV6AddrMask:
		value := fwpV6AddrAndMask{addr: condition.bytes, prefixLength: condition.prefixLength}
		return fwpValue0{typ: fwpV6AddrMask, value: uintptr(unsafe.Pointer(arenaNew(a, value)))}, nil
	default:
		return fwpValue0{}, fmt.Errorf("enforcement: unsupported WFP condition type %d", condition.kind)
	}
}

// marshal builds the FWPM_FILTER0 for spec in hub-net's sublayer.
func (a *wfpArena) marshal(spec filterSpec) (*fwpmFilter0, error) {
	display, err := a.displayData(spec.name, "hub-net overlay port policy")
	if err != nil {
		return nil, err
	}
	conditions := make([]fwpmFilterCondition0, len(spec.conditions))
	a.keep = append(a.keep, conditions)
	for index, condition := range spec.conditions {
		value, err := a.conditionValue(condition)
		if err != nil {
			return nil, err
		}
		conditions[index] = fwpmFilterCondition0{fieldKey: condition.field, matchType: fwpMatchEqual, conditionValue: value}
	}
	filter := arenaNew(a, fwpmFilter0{
		displayData:         display,
		flags:               fwpmFilterClearAR,
		providerKey:         &hubNetProviderKey,
		layerKey:            fwpmLayerALEAuthRecvAcceptV4,
		subLayerKey:         hubNetSublayerKey,
		weight:              fwpValue0{typ: fwpUint8, value: uintptr(spec.weight)},
		numFilterConditions: uint32(len(conditions)),
		action:              fwpmAction0{typ: fwpActionBlock},
	})
	if len(conditions) > 0 {
		filter.filterCondition = &conditions[0]
	}
	if spec.ipv6 {
		filter.layerKey = fwpmLayerALEAuthRecvAcceptV6
	}
	if spec.permit {
		filter.action.typ = fwpActionPermit
	}
	return filter, nil
}

// wfpEngine is the process's one dynamic WFP session. Every backend in the
// process shares it (provider and sublayer keys are fixed, and a key can be
// added once), and all calls on it are serialized, since a WFP transaction
// belongs to the session handle. When the process exits, however it exits,
// Windows closes the session and deletes every object added through it.
type wfpEngine struct {
	mu     sync.Mutex
	handle uintptr
	refs   int
}

var sharedWFPEngine wfpEngine

// acquire opens the session and registers the provider and sublayer on first
// use.
func (e *wfpEngine) acquire() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.refs > 0 {
		e.refs++
		return nil
	}
	var arena wfpArena
	display, err := arena.displayData("hub-net", "hub-net agent dynamic session")
	if err != nil {
		return err
	}
	session := arenaNew(&arena, fwpmSession0{
		displayData:          display,
		flags:                fwpmSessionDynamic,
		txnWaitTimeoutInMSec: wfpTxnWaitTimeoutMs,
	})
	var handle uintptr
	if err := fwpmEngineOpen0(session, &handle); err != nil {
		return fmt.Errorf("enforcement: open WFP engine: %w", err)
	}
	err = runWFPTransaction(handle, func(handle uintptr) error {
		providerDisplay, err := arena.displayData("hub-net", "hub-net overlay port policy")
		if err != nil {
			return err
		}
		provider := arenaNew(&arena, fwpmProvider0{providerKey: hubNetProviderKey, displayData: providerDisplay})
		if err := fwpmProviderAdd0(handle, provider); err != nil {
			return err
		}
		sublayerDisplay, err := arena.displayData("hub-net overlay ports", "Which overlay peers reach which local ports")
		if err != nil {
			return err
		}
		sublayer := arenaNew(&arena, fwpmSublayer0{
			subLayerKey: hubNetSublayerKey, displayData: sublayerDisplay,
			providerKey: &hubNetProviderKey, weight: hubNetSublayerWeight,
		})
		return fwpmSubLayerAdd0(handle, sublayer)
	})
	runtime.KeepAlive(&arena)
	if err != nil {
		_ = fwpmEngineClose0(handle)
		if isWFPCode(err, fwpEAlreadyExists) {
			return fmt.Errorf("enforcement: register WFP provider (is another hub-net agent running?): %w", err)
		}
		return fmt.Errorf("enforcement: register WFP provider: %w", err)
	}
	e.handle = handle
	e.refs = 1
	return nil
}

// release drops one reference; the last one closes the session, which
// deletes the provider, the sublayer and any filter still in it.
func (e *wfpEngine) release() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.refs == 0 {
		return nil
	}
	e.refs--
	if e.refs > 0 {
		return nil
	}
	handle := e.handle
	e.handle = 0
	if err := fwpmEngineClose0(handle); err != nil {
		return fmt.Errorf("enforcement: close WFP engine: %w", err)
	}
	return nil
}

// transact runs operation in one WFP transaction on the shared session.
func (e *wfpEngine) transact(operation func(handle uintptr) error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.refs == 0 {
		return errors.New("enforcement: WFP engine closed")
	}
	return runWFPTransaction(e.handle, operation)
}

func runWFPTransaction(handle uintptr, operation func(handle uintptr) error) error {
	if err := fwpmTransactionBegin0(handle); err != nil {
		return err
	}
	if err := operation(handle); err != nil {
		_ = fwpmTransactionAbort0(handle)
		return err
	}
	if err := fwpmTransactionCommit0(handle); err != nil {
		_ = fwpmTransactionAbort0(handle)
		return err
	}
	return nil
}
