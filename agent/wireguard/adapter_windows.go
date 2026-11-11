// adapter_windows.go implements the WireGuard Adapter on Windows with
// WireGuardNT (wireguard.dll, the kernel driver wireguard-windows ships),
// through golang.zx2c4.com/wireguard/windows/driver, and sets the interface's
// addresses, MTU and overlay routes with the IP Helper API (winipcfg).
//
// A WireGuardNT adapter lives as long as a handle to it is open: closing the
// last handle deletes the network adapter with its addresses and routes, so a
// crashed agent leaves nothing behind. The handles are kept per process by
// name, so the adapter a join brings up (its temporary bootstrap link) is the
// one the membership's session adopts, as the Linux kernel interface is.
//
// wireguard.dll must sit next to hub-net.exe (or in System32); the agent runs
// as an elevated service (LocalSystem) to create adapters and routes.

//go:build windows

package wireguard

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// TunnelType is the WireGuardNT tunnel type of Hub Network adapters, shown
// as the adapter's description in Windows.
const TunnelType = "Hub Network"

// windowsMTU matches kernel WireGuard's default on Linux.
const windowsMTU = 1420

// ntAdapter is one open WireGuardNT adapter.
type ntAdapter struct {
	adapter *driver.Adapter
	luid    winipcfg.LUID
}

// ntAdapters holds this process's open adapters by name.
var ntAdapters = struct {
	sync.Mutex
	byName map[string]*ntAdapter
}{byName: make(map[string]*ntAdapter)}

type windowsAdapter struct {
	name string

	mu     sync.Mutex
	up     bool
	config InterfaceConfig
}

func newOSAdapter(name string) Adapter {
	if name == "" {
		name = "hubnet0"
	}
	return &windowsAdapter{name: name}
}

// probeOSSupport loads wireguard.dll the way the driver package does (from
// the executable's directory or System32) without creating an adapter.
func probeOSSupport() error {
	const searchApplicationDir, searchSystem32 = 0x00000200, 0x00000800
	module, err := windows.LoadLibraryEx("wireguard.dll", 0, searchApplicationDir|searchSystem32)
	if err != nil {
		return fmt.Errorf("wireguard: WireGuardNT (wireguard.dll next to hub-net.exe) unavailable: %w", err)
	}
	_ = windows.FreeLibrary(module)
	return nil
}

// adapterGUID derives the adapter's GUID from its name, so Windows keeps one
// network profile per Hub interface instead of a new one at every start.
func adapterGUID(name string) *windows.GUID {
	sum := sha256.Sum256([]byte("hub-net wireguardnt adapter " + name))
	guid := &windows.GUID{
		Data1: uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3]),
		Data2: uint16(sum[4])<<8 | uint16(sum[5]),
		Data3: uint16(sum[6])<<8 | uint16(sum[7]),
	}
	copy(guid.Data4[:], sum[8:16])
	guid.Data3 = guid.Data3&0x0fff | 0x5000 // name-based (version 5 layout)
	guid.Data4[0] = guid.Data4[0]&0x3f | 0x80
	return guid
}

// openOrCreate returns the process's adapter named name, creating it when
// none is open. created reports a new adapter, which a failed Up closes again.
func openOrCreate(name string) (handle *ntAdapter, created bool, err error) {
	ntAdapters.Lock()
	defer ntAdapters.Unlock()
	if handle = ntAdapters.byName[name]; handle != nil {
		return handle, false, nil
	}
	adapter, err := driver.CreateAdapter(name, TunnelType, adapterGUID(name))
	if err != nil {
		return nil, false, fmt.Errorf("create WireGuardNT adapter: %w", err)
	}
	handle = &ntAdapter{adapter: adapter, luid: adapter.LUID()}
	ntAdapters.byName[name] = handle
	return handle, true, nil
}

func lookupAdapter(name string) *ntAdapter {
	ntAdapters.Lock()
	defer ntAdapters.Unlock()
	return ntAdapters.byName[name]
}

// closeAdapter closes the named adapter's handle, which deletes the network
// adapter with its addresses and routes.
func closeAdapter(name string) error {
	ntAdapters.Lock()
	handle := ntAdapters.byName[name]
	delete(ntAdapters.byName, name)
	ntAdapters.Unlock()
	if handle == nil {
		return nil
	}
	return handle.adapter.Close()
}

func (a *windowsAdapter) Up(config InterfaceConfig) error {
	if err := ValidateAllowedIPs(collectAllowedIPs(config.Peers)); err != nil {
		return err
	}
	if err := validateEndpoints(config.Peers...); err != nil {
		return err
	}
	if config.Name == "" {
		config.Name = a.name
	} else {
		a.name = config.Name
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.up {
		return errors.New("wireguard: interface already up")
	}

	// HN-304: refuse a foreign route inside the overlay before creating
	// anything. Routes on this process's own adapter (a join's bootstrap link
	// being adopted) aren't foreign.
	var own winipcfg.LUID
	if existing := lookupAdapter(config.Name); existing != nil {
		own = existing.luid
	}
	selfAddrs := make([]netip.Addr, 0, 2)
	for _, address := range []netip.Addr{config.Address, config.AddressIPv6} {
		if address.IsValid() {
			selfAddrs = append(selfAddrs, address)
		}
	}
	foreign, err := foreignRoutes(own)
	if err != nil {
		return fmt.Errorf("wireguard: route table: %w", err)
	}
	if conflict, ok := FindOverlayRouteConflict(foreign, selfAddrs...); ok {
		return fmt.Errorf("%w: %s", ErrOverlayRouteConflict, conflict)
	}

	handle, created, err := openOrCreate(config.Name)
	if err != nil {
		return fmt.Errorf("wireguard: %w", err)
	}
	fail := func(err error) error {
		if created {
			_ = closeAdapter(config.Name)
		}
		return err
	}
	if err := setConfiguration(handle.adapter, config, true, false); err != nil {
		return fail(fmt.Errorf("wireguard: configure interface: %w", err))
	}
	if err := handle.adapter.SetAdapterState(driver.AdapterStateUp); err != nil {
		return fail(fmt.Errorf("wireguard: bring interface up: %w", err))
	}
	setInterfaceMTU(handle.luid)
	for _, address := range selfAddrs {
		if err := handle.luid.AddIPAddress(netip.PrefixFrom(address, address.BitLen())); err != nil && !alreadyExists(err) {
			return fail(fmt.Errorf("wireguard: add address %s: %w", address, err))
		}
	}
	for _, route := range OverlayRoutes() {
		if route.Addr().Is6() && !config.AddressIPv6.IsValid() {
			continue
		}
		nextHop := netip.IPv4Unspecified()
		if route.Addr().Is6() {
			nextHop = netip.IPv6Unspecified()
		}
		if err := handle.luid.AddRoute(route, nextHop, 0); err != nil && !alreadyExists(err) {
			return fail(fmt.Errorf("wireguard: install overlay route %s: %w", route, err))
		}
	}
	a.config = config
	a.up = true
	return nil
}

// alreadyExists reports ERROR_OBJECT_ALREADY_EXISTS, which adding an address
// or route an adopted adapter already has returns.
func alreadyExists(err error) bool {
	return errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS)
}

// setInterfaceMTU sets the adapter's IPv4 and IPv6 MTU. IPv6 may be off on
// the host; that, and any other failure, leaves Windows' default.
func setInterfaceMTU(luid winipcfg.LUID) {
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		row, err := luid.IPInterface(family)
		if err != nil {
			continue
		}
		row.NLMTU = windowsMTU
		_ = row.Set()
	}
}

// foreignRoutes lists the destination prefixes of every route not on own.
func foreignRoutes(own winipcfg.LUID) ([]netip.Prefix, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(rows))
	for i := range rows {
		if own != 0 && rows[i].InterfaceLUID == own {
			continue
		}
		prefix := rows[i].DestinationPrefix.Prefix()
		if prefix.IsValid() {
			out = append(out, prefix)
		}
	}
	return out, nil
}

// setConfiguration applies config through WireGuardSetConfiguration.
// replacePeers drops peers not listed; remove removes the listed peers.
func setConfiguration(adapter *driver.Adapter, config InterfaceConfig, replacePeers, remove bool) error {
	var builder driver.ConfigBuilder
	size := unsafe.Sizeof(driver.Interface{})
	for _, peer := range config.Peers {
		size += unsafe.Sizeof(driver.Peer{}) + uintptr(len(peer.AllowedIPs))*unsafe.Sizeof(driver.AllowedIP{})
	}
	builder.Preallocate(uint32(size))
	iface := driver.Interface{PeerCount: uint32(len(config.Peers))}
	if len(config.PrivateKey) == 32 {
		iface.Flags |= driver.InterfaceHasPrivateKey
		copy(iface.PrivateKey[:], config.PrivateKey)
	}
	if config.ListenPort != 0 {
		iface.Flags |= driver.InterfaceHasListenPort
		iface.ListenPort = config.ListenPort
	}
	if replacePeers {
		iface.Flags |= driver.InterfaceReplacePeers
	}
	builder.AppendInterface(&iface)
	for _, peer := range config.Peers {
		if len(peer.PublicKey) != 32 {
			return fmt.Errorf("peer public key is %d bytes", len(peer.PublicKey))
		}
		entry := driver.Peer{Flags: driver.PeerHasPublicKey}
		copy(entry.PublicKey[:], peer.PublicKey)
		if remove {
			entry.Flags |= driver.PeerRemove
			builder.AppendPeer(&entry)
			continue
		}
		if peer.Endpoint != "" {
			addrPort, err := netip.ParseAddrPort(peer.Endpoint)
			if err != nil {
				return fmt.Errorf("endpoint %q: %w", peer.Endpoint, err)
			}
			if err := entry.Endpoint.SetAddrPort(addrPort); err != nil {
				return fmt.Errorf("endpoint %q: %w", peer.Endpoint, err)
			}
			entry.Flags |= driver.PeerHasEndpoint
		}
		if peer.PersistentKeepalive != 0 {
			entry.Flags |= driver.PeerHasPersistentKeepalive
			entry.PersistentKeepalive = peer.PersistentKeepalive
		}
		entry.Flags |= driver.PeerReplaceAllowedIPs
		entry.AllowedIPsCount = uint32(len(peer.AllowedIPs))
		builder.AppendPeer(&entry)
		for _, prefix := range peer.AllowedIPs {
			allowed := driver.AllowedIP{Cidr: uint8(prefix.Bits())}
			if prefix.Addr().Is4() {
				allowed.AddressFamily = windows.AF_INET
				v4 := prefix.Addr().As4()
				copy(allowed.Address[:], v4[:])
			} else {
				allowed.AddressFamily = windows.AF_INET6
				v6 := prefix.Addr().As16()
				copy(allowed.Address[:], v6[:])
			}
			builder.AppendAllowedIP(&allowed)
		}
	}
	configuration, configSize := builder.Interface()
	return adapter.SetConfiguration(configuration, configSize)
}

func (a *windowsAdapter) Down() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.up {
		return nil
	}
	err := closeAdapter(a.config.Name)
	a.up = false
	a.config = InterfaceConfig{}
	return err
}

func (a *windowsAdapter) AddPeer(peer PeerConfig) error {
	if err := ValidateAllowedIPs(peer.AllowedIPs); err != nil {
		return err
	}
	if err := validateEndpoints(peer); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.up {
		return errors.New("wireguard: interface is down")
	}
	handle := lookupAdapter(a.config.Name)
	if handle == nil {
		return errors.New("wireguard: adapter closed")
	}
	if err := setConfiguration(handle.adapter, InterfaceConfig{Peers: []PeerConfig{peer}}, false, false); err != nil {
		return fmt.Errorf("wireguard: add peer: %w", err)
	}
	for index, existing := range a.config.Peers {
		if string(existing.PublicKey) == string(peer.PublicKey) {
			if peer.Endpoint == "" {
				peer.Endpoint = existing.Endpoint
			}
			a.config.Peers[index] = peer
			return nil
		}
	}
	a.config.Peers = append(a.config.Peers, peer)
	return nil
}

func (a *windowsAdapter) RemovePeer(publicKey []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.up {
		return errors.New("wireguard: interface is down")
	}
	handle := lookupAdapter(a.config.Name)
	if handle == nil {
		return errors.New("wireguard: adapter closed")
	}
	if err := setConfiguration(handle.adapter, InterfaceConfig{Peers: []PeerConfig{{PublicKey: publicKey}}}, false, true); err != nil {
		return fmt.Errorf("wireguard: remove peer: %w", err)
	}
	next := a.config.Peers[:0]
	for _, p := range a.config.Peers {
		if string(p.PublicKey) != string(publicKey) {
			next = append(next, p)
		}
	}
	a.config.Peers = next
	return nil
}

func (a *windowsAdapter) State() (InterfaceConfig, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.up {
		return InterfaceConfig{}, false
	}
	out := a.config
	out.Peers = append([]PeerConfig(nil), a.config.Peers...)
	return out, true
}

// LastHandshakes reads each peer's latest handshake from WireGuardNT, keyed by
// the base64 public key; peers that never completed one are left out.
func (a *windowsAdapter) LastHandshakes() (map[string]time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.up {
		return nil, errors.New("wireguard: interface is down")
	}
	handle := lookupAdapter(a.config.Name)
	if handle == nil {
		return nil, errors.New("wireguard: adapter closed")
	}
	configuration, err := handle.adapter.Configuration()
	if err != nil {
		return nil, fmt.Errorf("wireguard: get configuration: %w", err)
	}
	out := make(map[string]time.Time)
	peer := configuration.FirstPeer()
	for i := uint32(0); i < configuration.PeerCount; i++ {
		if peer.LastHandshake != 0 {
			out[base64.StdEncoding.EncodeToString(peer.PublicKey[:])] = filetimeToTime(peer.LastHandshake)
		}
		peer = peer.NextPeer()
	}
	return out, nil
}

// filetimeToTime converts 100 ns intervals since 1601 to a time.
func filetimeToTime(filetime uint64) time.Time {
	ft := windows.Filetime{LowDateTime: uint32(filetime), HighDateTime: uint32(filetime >> 32)}
	return time.Unix(0, ft.Nanoseconds())
}
