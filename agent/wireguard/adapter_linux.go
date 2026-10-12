// adapter_linux.go implements the WireGuard Adapter for Linux using the kernel
// WireGuard module through generic netlink (WG_CMD_SET_DEVICE / GET_DEVICE)
// and classic rtnetlink for interface creation (RTM_NEWLINK with
// IFLA_LINKINFO/KIND="wireguard"), address assignment (RTM_NEWADDR), and
// teardown (RTM_DELLINK).
//
// Scope (HN-303): full interface lifecycle Up/Down/AddPeer/RemovePeer/State.
// Route installation for the overlay prefixes is HN-304; this adapter only
// configures the interface address and per-peer AllowedIPs, both validated
// against the frozen overlay ranges before any netlink call.
//
// The adapter is single-use per Agent process: Up opens a netlink socket and
// resolves the "wireguard" genetlink family id once, caches both for the
// process lifetime, and Down closes them. Concurrent calls are serialized by
// the mutex; netlink is request/response over a single socket per process.

//go:build linux

package wireguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// WireGuardGenlName is the genetlink family name published by the kernel
// WireGuard module. Hardcoded by the kernel ABI.
const WireGuardGenlName = "wireguard"

// WireGuardGenlVersion is the genetlink protocol version the adapter targets.
const WireGuardGenlVersion = 1

// netlinkRecvTimeoutSec bounds a blocking Recvfrom so a missing kernel ACK
// surfaces as a timeout rather than hanging the agent forever.
const netlinkRecvTimeoutSec = 5

// linuxAdapter drives the kernel WireGuard module over netlink.
type linuxAdapter struct {
	name string

	mu       sync.Mutex
	fd       int // NETLINK_GENERIC: WireGuard genetlink control
	routeFD  int // NETLINK_ROUTE: links, addresses, and routes
	familyID uint16
	seq      uint32
	up       bool
	config   InterfaceConfig
}

// newOSAdapter returns a Linux kernel-netlink WireGuard adapter.
func newOSAdapter(name string) Adapter {
	if name == "" {
		name = "hubnet0"
	}
	return &linuxAdapter{name: name}
}

func probeOSSupport() error {
	fd, err := openNetlinkSocket()
	if err != nil {
		return fmt.Errorf("wireguard: open netlink probe: %w", err)
	}
	defer unix.Close(fd)

	a := &linuxAdapter{fd: fd}
	if _, err := a.resolveFamily(); err != nil {
		return fmt.Errorf("wireguard: kernel support unavailable: %w", err)
	}
	return nil
}

// Up brings the interface up with config. AllowedIPs are validated BEFORE any
// socket is opened: this is the deterministic, privilege-free gate asserted by
// the OS-agnostic platform_test.go.
func (a *linuxAdapter) Up(config InterfaceConfig) error {
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
	if a.fd <= 0 {
		fd, err := openNetlinkSocket()
		if err != nil {
			return err
		}
		a.fd = fd
	}
	if a.routeFD <= 0 {
		fd, err := openRouteNetlinkSocket()
		if err != nil {
			_ = unix.Close(a.fd)
			a.fd = 0
			return err
		}
		a.routeFD = fd
	}
	if a.familyID == 0 {
		fid, err := a.resolveFamily()
		if err != nil {
			return err
		}
		a.familyID = fid
	}

	// HN-304: refuse to start if a foreign route already owns the overlay
	// prefixes. The pre-check dumps the main table before creating the
	// interface so a conflict never leaves a half-configured device behind.
	// Routes bound to this profile interface (from a prior agent run that did
	// not tear down cleanly) are NOT conflicts: the install path co-opts them
	// with NLM_F_REPLACE. The agent's own self-routes (host /32 /128 for its
	// assigned overlay addresses) are likewise exempt.
	preOwn, preForeign, err := a.existingOverlayRoutesLocked(a.nameIndexMaybe(config.Name))
	if err != nil {
		return fmt.Errorf("wireguard: route dump: %w", err)
	}
	selfAddrs := make([]netip.Addr, 0, 1)
	if config.Address.IsValid() {
		selfAddrs = append(selfAddrs, config.Address)
	}
	if conflict, ok := FindOverlayRouteConflict(preForeign, selfAddrs...); ok {
		return fmt.Errorf("%w: %s", ErrOverlayRouteConflict, conflict)
	}
	_ = preOwn // leftovers co-opted below; no action needed at pre-check time.

	// Create the WireGuard interface (idempotent: ignore EEXIST), then push
	// the full device configuration with REPLACE_PEERS.
	if err := a.createInterfaceLocked(config.Name); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("wireguard: create interface %s: %w", config.Name, err)
	}
	if err := a.setDeviceLocked(config, true /*replacePeers*/, false /*removePeer*/); err != nil {
		// Roll back: drop the interface so a retry starts clean.
		_ = a.deleteInterfaceLocked(config.Name)
		return fmt.Errorf("wireguard: configure interface: %w", err)
	}
	if config.Address.IsValid() {
		// Address assignment is best-effort at this layer: a stale address
		// from a prior run is not fatal. Diagnostics surface via State().
		_ = a.addAddressLocked(config.Name, config.Address)
	}
	if err := a.setUpFlagLocked(config.Name); err != nil {
		// Roll back: drop the interface so a retry starts clean.
		_ = a.deleteInterfaceLocked(config.Name)
		return fmt.Errorf("wireguard: bring interface up: %w", err)
	}

	// HN-304: install the scoped overlay routes. Only the frozen overlay
	// prefixes are added (see OverlayRoutes); neither is a default route, so
	// the default internet path is untouched. NLM_F_REPLACE makes the install
	// idempotent: a leftover route the prior agent run bound to this interface
	// is co-opted. On failure the adapter rolls back to the pre-Up state:
	// routes installed so far are removed and the interface is torn down. A
	// retry starts clean.
	idx, err := a.ifIndexLocked(config.Name)
	if err != nil {
		_ = a.deleteInterfaceLocked(config.Name)
		return fmt.Errorf("wireguard: resolve ifindex for routes: %w", err)
	}
	installed := make([]netip.Prefix, 0, 2)
	for _, route := range OverlayRoutes() {
		if err := a.installOverlayRouteLocked(route, idx, config.Address); err != nil {
			// Roll back the routes we did install, then drop the interface.
			for _, done := range installed {
				_ = a.uninstallOverlayRouteLocked(done, idx)
			}
			_ = a.deleteInterfaceLocked(config.Name)
			return fmt.Errorf("wireguard: install overlay route %s: %w", route, err)
		}
		installed = append(installed, route)
	}
	a.config = config
	a.up = true
	return nil
}

// nameIndexMaybe resolves the interface index for name if the interface
// already exists, returning 0 otherwise. Used by Up's pre-check to identify
// routes the prior agent run bound to this profile interface (so a leftover
// own-route is not mistaken for a foreign conflict). A name that has no
// interface yet simply yields 0, which matches no OIF in the dump.
func (a *linuxAdapter) nameIndexMaybe(name string) int32 {
	idx, err := a.ifIndexLocked(name)
	if err != nil {
		return 0
	}
	return idx
}

// Down tears the interface down and closes the socket.
func (a *linuxAdapter) Down() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.up {
		return nil
	}
	name := a.config.Name
	// HN-304: explicitly remove the overlay routes before tearing the
	// interface down. Deleting the interface already drops its routes, but a
	// direct DELROUTE keeps the teardown path self-contained and surfaces
	// any unexpected route-table corruption via diagnostics. Errors here are
	// non-fatal: the interface deletion below is the authoritative cleanup.
	if idx, err := a.ifIndexLocked(name); err == nil {
		for _, route := range OverlayRoutes() {
			_ = a.uninstallOverlayRouteLocked(route, idx)
		}
	}
	_ = a.deleteInterfaceLocked(name)
	a.up = false
	a.config = InterfaceConfig{}
	if a.fd > 0 {
		_ = unix.Close(a.fd)
		a.fd = 0
	}
	if a.routeFD > 0 {
		_ = unix.Close(a.routeFD)
		a.routeFD = 0
	}
	a.familyID = 0
	return nil
}

// AddPeer adds a peer without disturbing others. The peer carries
// REPLACE_ALLOWEDIPS so its AllowedIPs fully replace any prior set for that
// public key; REPLACE_PEERS is false so other peers are untouched.
func (a *linuxAdapter) AddPeer(peer PeerConfig) error {
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
	cfg := InterfaceConfig{
		Name:       a.config.Name,
		PrivateKey: a.config.PrivateKey,
		ListenPort: a.config.ListenPort,
		Peers:      []PeerConfig{peer},
	}
	if err := a.setDeviceLocked(cfg, false, false); err != nil {
		return fmt.Errorf("wireguard: add peer: %w", err)
	}
	// AddPeer also updates an existing peer (its AllowedIPs are replaced).
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

// RemovePeer removes a peer by public key (WGPEER_F_REMOVE_ME).
func (a *linuxAdapter) RemovePeer(publicKey []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.up {
		return errors.New("wireguard: interface is down")
	}
	cfg := InterfaceConfig{
		Name:       a.config.Name,
		PrivateKey: a.config.PrivateKey,
		ListenPort: a.config.ListenPort,
		Peers:      []PeerConfig{{PublicKey: publicKey}},
	}
	if err := a.setDeviceLocked(cfg, false, true /*removePeer*/); err != nil {
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

// State reports the cached configuration. It does not re-query the kernel; the
// adapter is the authoritative record of what it configured.
func (a *linuxAdapter) State() (InterfaceConfig, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.up {
		return InterfaceConfig{}, false
	}
	out := a.config
	out.Peers = append([]PeerConfig(nil), a.config.Peers...)
	return out, true
}

// ---- genetlink family resolution ----

func (a *linuxAdapter) resolveFamily() (uint16, error) {
	hdrLen := unix.NLMSG_HDRLEN + genlmsghdrLen
	w := newNlmsgWriter(make([]byte, hdrLen))
	binary.LittleEndian.PutUint16(w.buf[4:], unix.GENL_ID_CTRL)
	binary.LittleEndian.PutUint16(w.buf[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	w.buf[unix.NLMSG_HDRLEN] = byte(unix.CTRL_CMD_GETFAMILY)
	w.buf[unix.NLMSG_HDRLEN+1] = WireGuardGenlVersion
	w.PutString(unix.CTRL_ATTR_FAMILY_NAME, WireGuardGenlName)
	body := w.Bytes()

	if err := a.send(body); err != nil {
		return 0, fmt.Errorf("wireguard: send genl resolve: %w", err)
	}
	reply, err := a.recv()
	if err != nil {
		return 0, fmt.Errorf("wireguard: recv genl resolve: %w", err)
	}
	if err := ackOrError(reply); err != nil {
		return 0, fmt.Errorf("wireguard: genl resolve: %w", err)
	}
	// Find the NEWFAMILY response and walk its attributes for FAMILY_ID.
	for _, msg := range splitMessages(reply) {
		msgType, _, msgBody, err := parseNlmsghdr(msg)
		if err != nil || msgType == unix.NLMSG_ERROR {
			continue
		}
		_, _, attrBody, err := parseGenlmsghdr(msgBody)
		if err != nil {
			continue
		}
		r := newNlmsgReader(attrBody, 0)
		for {
			at, payload, ok := r.Next()
			if !ok {
				break
			}
			if at == unix.CTRL_ATTR_FAMILY_ID && len(payload) >= 2 {
				return binary.LittleEndian.Uint16(payload), nil
			}
		}
	}
	return 0, errors.New("wireguard: genl reply missing family id")
}

// ---- device configuration ----

// setDeviceLocked builds and sends a WG_CMD_SET_DEVICE message. replacePeers
// controls WGDEVICE_F_REPLACE_PEERS; removePeer makes the single peer carry
// WGPEER_F_REMOVE_ME.
func (a *linuxAdapter) setDeviceLocked(config InterfaceConfig, replacePeers, removePeer bool) error {
	body := a.encodeSetDevice(config, replacePeers, removePeer)
	if err := a.send(body); err != nil {
		return err
	}
	reply, err := a.recv()
	if err != nil {
		return err
	}
	return ackOrError(reply)
}

func (a *linuxAdapter) encodeSetDevice(config InterfaceConfig, replacePeers, removePeer bool) []byte {
	hdrLen := unix.NLMSG_HDRLEN + genlmsghdrLen
	w := newNlmsgWriter(make([]byte, hdrLen))
	binary.LittleEndian.PutUint16(w.buf[4:], a.familyID)
	binary.LittleEndian.PutUint16(w.buf[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	w.buf[unix.NLMSG_HDRLEN] = byte(unix.WG_CMD_SET_DEVICE)
	w.buf[unix.NLMSG_HDRLEN+1] = WireGuardGenlVersion

	w.PutString(unix.WGDEVICE_A_IFNAME, config.Name)
	if len(config.PrivateKey) == 32 {
		w.PutBytes(unix.WGDEVICE_A_PRIVATE_KEY, config.PrivateKey)
	}
	if config.ListenPort != 0 {
		w.PutUint16(unix.WGDEVICE_A_LISTEN_PORT, config.ListenPort)
	}
	if replacePeers {
		w.PutUint32(unix.WGDEVICE_A_FLAGS, unix.WGDEVICE_F_REPLACE_PEERS)
	}
	if len(config.Peers) > 0 {
		peersOff := w.PutNested(unix.WGDEVICE_A_PEERS)
		for _, p := range config.Peers {
			encodePeer(w, p, removePeer)
		}
		w.CloseNested(peersOff)
	}
	return w.Bytes()
}

// encodePeer appends one WGPEER_A_* nested attribute. When remove is true the
// peer carries only PUBLIC_KEY + FLAGS(WGPEER_F_REMOVE_ME). Otherwise
// PUBLIC_KEY + ALLOWEDIPS (+ optional ENDPOINT) plus
// WGPEER_F_REPLACE_ALLOWEDIPS so this peer's AllowedIPs are fully replaced.
func encodePeer(w *nlmsgWriter, peer PeerConfig, remove bool) {
	off := w.PutNested(unix.WGPEER_A_PUBLIC_KEY)
	w.PutBytes(unix.WGPEER_A_PUBLIC_KEY, peer.PublicKey)
	if remove {
		w.PutUint32(unix.WGPEER_A_FLAGS, unix.WGPEER_F_REMOVE_ME)
		w.CloseNested(off)
		return
	}
	if peer.Endpoint != "" {
		// Up and AddPeer validate endpoints before encoding.
		if sockaddr, err := endpointSockaddr(peer.Endpoint); err == nil {
			w.PutBytes(unix.WGPEER_A_ENDPOINT, sockaddr)
		}
	}
	if len(peer.AllowedIPs) > 0 {
		allowedOff := w.PutNested(unix.WGPEER_A_ALLOWEDIPS)
		for _, prefix := range peer.AllowedIPs {
			encodeAllowedIP(w, prefix)
		}
		w.CloseNested(allowedOff)
	}
	w.PutUint32(unix.WGPEER_A_FLAGS, unix.WGPEER_F_REPLACE_ALLOWEDIPS)
	w.CloseNested(off)
}

// encodeAllowedIP appends one WGALLOWEDIP_A_* nested attribute.
func encodeAllowedIP(w *nlmsgWriter, prefix netip.Prefix) {
	off := w.PutNested(unix.WGALLOWEDIP_A_UNSPEC + 1)
	if prefix.Addr().Is4() {
		w.PutUint16(unix.WGALLOWEDIP_A_FAMILY, unix.AF_INET)
		w.PutBytes(unix.WGALLOWEDIP_A_IPADDR, prefix.Addr().AsSlice())
		w.PutUint8(unix.WGALLOWEDIP_A_CIDR_MASK, uint8(prefix.Bits()))
	} else {
		w.PutUint16(unix.WGALLOWEDIP_A_FAMILY, unix.AF_INET6)
		w.PutBytes(unix.WGALLOWEDIP_A_IPADDR, addr16Slice(prefix.Addr()))
		w.PutUint8(unix.WGALLOWEDIP_A_CIDR_MASK, uint8(prefix.Bits()))
	}
	w.CloseNested(off)
}

// addr16Slice returns a 16-byte netip.Addr6 address as a slice so it can be
// passed to PutBytes (which takes []byte, not [16]byte).
func addr16Slice(addr netip.Addr) []byte {
	b16 := addr.As16()
	return b16[:]
}

// ---- rtnetlink: interface create / delete / address / up flag ----

// ifinfomsg is the rtnetlink link message header (hand-rolled because x/sys
// does not export it). Layout: family(u8), pad(u8), type(u16), index(i32),
// flags(u32), changemask(u32).
type ifinfomsg struct {
	Family     uint8
	_          uint8
	Type       uint16
	Index      int32
	Flags      uint32
	ChangeMask uint32
}

const sizeofIfinfomsg = int(unsafe.Sizeof(ifinfomsg{}))

// ifaddrmsg is the rtnetlink address message header.
type ifaddrmsg struct {
	Family    uint8
	PrefixLen uint8
	Flags     uint8
	Scope     uint8
	Index     uint32
}

const sizeofIfaddrmsg = int(unsafe.Sizeof(ifaddrmsg{}))

func (a *linuxAdapter) createInterfaceLocked(name string) error {
	return a.sendRecvRouteAck(buildNewLinkMessage(name), "create interface")
}

func (a *linuxAdapter) deleteInterfaceLocked(name string) error {
	idx, err := a.ifIndexLocked(name)
	if err != nil {
		return err
	}
	hdr := make([]byte, unix.NLMSG_HDRLEN+sizeofIfinfomsg)
	binary.LittleEndian.PutUint32(hdr, uint32(len(hdr)))
	binary.LittleEndian.PutUint16(hdr[4:], unix.RTM_DELLINK)
	binary.LittleEndian.PutUint16(hdr[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	inf := ifinfomsg{Family: unix.AF_UNSPEC, Index: idx}
	putIfinfomsg(hdr[unix.NLMSG_HDRLEN:], &inf)
	return a.sendRecvRouteAck(hdr, "delete interface")
}

func (a *linuxAdapter) addAddressLocked(name string, addr netip.Addr) error {
	idx, err := a.ifIndexLocked(name)
	if err != nil {
		return err
	}
	var family uint8
	var prefixLen uint8
	var ipBytes []byte
	if addr.Is4() {
		family = unix.AF_INET
		prefixLen = 32
		ipBytes = addr.AsSlice()
	} else {
		family = unix.AF_INET6
		prefixLen = 128
		b16 := addr.As16()
		ipBytes = b16[:]
	}
	hdr := make([]byte, unix.NLMSG_HDRLEN+sizeofIfaddrmsg)
	binary.LittleEndian.PutUint16(hdr[4:], unix.RTM_NEWADDR)
	binary.LittleEndian.PutUint16(hdr[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	am := ifaddrmsg{Family: family, PrefixLen: prefixLen, Scope: unix.RT_SCOPE_UNIVERSE, Index: uint32(idx)}
	putIfaddrmsg(hdr[unix.NLMSG_HDRLEN:], &am)
	w := newNlmsgWriter(hdr)
	w.PutBytes(unix.IFA_LOCAL, ipBytes)
	w.PutBytes(unix.IFA_ADDRESS, ipBytes)
	return a.sendRecvRouteAck(w.Bytes(), "add address")
}

func (a *linuxAdapter) setUpFlagLocked(name string) error {
	idx, err := a.ifIndexLocked(name)
	if err != nil {
		return err
	}
	hdr := make([]byte, unix.NLMSG_HDRLEN+sizeofIfinfomsg)
	binary.LittleEndian.PutUint32(hdr, uint32(len(hdr)))
	binary.LittleEndian.PutUint16(hdr[4:], unix.RTM_NEWLINK)
	binary.LittleEndian.PutUint16(hdr[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	inf := ifinfomsg{Family: unix.AF_UNSPEC, Index: idx, Flags: unix.IFF_UP, ChangeMask: unix.IFF_UP}
	putIfinfomsg(hdr[unix.NLMSG_HDRLEN:], &inf)
	return a.sendRecvRouteAck(hdr, "set ifflags")
}

// buildNewLinkMessage constructs RTM_NEWLINK with nested IFLA_LINKINFO
// KIND="wireguard". This is the canonical way to create a WireGuard interface.
func buildNewLinkMessage(name string) []byte {
	hdr := make([]byte, unix.NLMSG_HDRLEN+sizeofIfinfomsg)
	binary.LittleEndian.PutUint16(hdr[4:], unix.RTM_NEWLINK)
	binary.LittleEndian.PutUint16(hdr[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	inf := ifinfomsg{Family: unix.AF_UNSPEC, Type: 1 /*ARPHRD_NONE*/}
	putIfinfomsg(hdr[unix.NLMSG_HDRLEN:], &inf)
	w := newNlmsgWriter(hdr)
	w.PutString(unix.IFLA_IFNAME, name)
	linkInfoOff := w.PutNested(unix.IFLA_LINKINFO)
	w.PutString(unix.IFLA_INFO_KIND, "wireguard")
	w.CloseNested(linkInfoOff)
	return w.Bytes()
}

func putIfinfomsg(dst []byte, inf *ifinfomsg) {
	dst[0] = inf.Family
	binary.LittleEndian.PutUint16(dst[2:], inf.Type)
	binary.LittleEndian.PutUint32(dst[4:], uint32(inf.Index))
	binary.LittleEndian.PutUint32(dst[8:], inf.Flags)
	binary.LittleEndian.PutUint32(dst[12:], inf.ChangeMask)
}

func putIfaddrmsg(dst []byte, am *ifaddrmsg) {
	dst[0] = am.Family
	dst[1] = am.PrefixLen
	dst[2] = am.Flags
	dst[3] = am.Scope
	binary.LittleEndian.PutUint32(dst[4:], am.Index)
}

// ifIndexLocked resolves interface name -> index via SIOCGIFINDEX ioctl.
func (a *linuxAdapter) ifIndexLocked(name string) (int32, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
		if err != nil {
			return 0, fmt.Errorf("wireguard: control socket: %w", err)
		}
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, ifr); err != nil {
		return 0, fmt.Errorf("wireguard: ifindex %s: %w", name, err)
	}
	return int32(ifr.Uint32()), nil
}

// ---- low-level netlink send/recv ----

// openNetlinkSocket opens an AF_NETLINK / NETLINK_GENERIC socket bound to pid 0.
func openNetlinkSocket() (int, error) {
	return openNetlinkSocketProtocol(unix.NETLINK_GENERIC)
}

func openRouteNetlinkSocket() (int, error) {
	return openNetlinkSocketProtocol(unix.NETLINK_ROUTE)
}

func openNetlinkSocketProtocol(protocol int) (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, protocol)
	if err != nil {
		return -1, fmt.Errorf("wireguard: netlink socket: %w", err)
	}
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("wireguard: netlink bind: %w", err)
	}
	return fd, nil
}

func (a *linuxAdapter) send(msg []byte) error {
	return a.sendOn(a.fd, msg)
}

func (a *linuxAdapter) sendRoute(msg []byte) error {
	return a.sendOn(a.routeFD, msg)
}

func (a *linuxAdapter) sendOn(fd int, msg []byte) error {
	a.seq++
	binary.LittleEndian.PutUint32(msg[8:], a.seq) // Seq
	binary.LittleEndian.PutUint32(msg[12:], 0)    // Pid (kernel expects 0)
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	return unix.Sendto(fd, msg, 0, sa)
}

func (a *linuxAdapter) recv() ([]byte, error) {
	return recvNetlink(a.fd)
}

func recvNetlink(fd int) ([]byte, error) {
	tv := &unix.Timeval{Sec: netlinkRecvTimeoutSec}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, tv)
	buf := make([]byte, 65536)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, err
	}
	if n < unix.NLMSG_HDRLEN {
		return nil, fmt.Errorf("wireguard: short netlink reply %d", n)
	}
	return append([]byte(nil), buf[:n]...), nil
}

func (a *linuxAdapter) sendRecvAck(msg []byte, what string) error {
	if err := a.send(msg); err != nil {
		return fmt.Errorf("wireguard: send %s: %w", what, err)
	}
	reply, err := a.recv()
	if err != nil {
		return fmt.Errorf("wireguard: recv %s: %w", what, err)
	}
	return ackOrError(reply)
}

func (a *linuxAdapter) sendRecvRouteAck(msg []byte, what string) error {
	if err := a.sendRoute(msg); err != nil {
		return fmt.Errorf("wireguard: send %s: %w", what, err)
	}
	reply, err := recvNetlink(a.routeFD)
	if err != nil {
		return fmt.Errorf("wireguard: recv %s: %w", what, err)
	}
	return ackOrError(reply)
}

// ackOrError inspects a netlink reply. NLMSG_ERROR with code==0 is an ACK; any
// non-zero code is returned as syscall.Errno (preserving EEXIST etc.).
func ackOrError(reply []byte) error {
	for _, msg := range splitMessages(reply) {
		msgType, _, body, err := parseNlmsghdr(msg)
		if err != nil {
			continue
		}
		if msgType != unix.NLMSG_ERROR {
			continue
		}
		if len(body) < 4 {
			return ErrTruncated
		}
		code := int32(binary.LittleEndian.Uint32(body))
		if code == 0 {
			return nil // ACK
		}
		return syscall.Errno(-code)
	}
	return nil
}

// splitMessages walks a netlink buffer into individual messages by Length.
func splitMessages(buf []byte) [][]byte {
	var out [][]byte
	for off := 0; off+unix.NLMSG_HDRLEN <= len(buf); {
		total := int(binary.LittleEndian.Uint32(buf[off:]))
		if total < unix.NLMSG_HDRLEN || off+total > len(buf) {
			break
		}
		out = append(out, buf[off:off+total])
		off += nlaAlign(total)
	}
	return out
}

// PutUint32 adds a uint32 NLA. Defined on nlmsgWriter here (Linux-only) so the
// OS-agnostic framing file stays minimal; netlink_test.go does not exercise it.
func (w *nlmsgWriter) PutUint32(attrType uint16, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	w.PutBytes(attrType, b[:])
}
