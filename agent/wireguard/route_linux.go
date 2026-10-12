// route_linux.go installs the scoped overlay routes for the Linux WireGuard
// adapter (HN-304). It adds the rtnetlink operations the adapter needs on top
// of the genetlink device configuration in adapter_linux.go:
//
//   - dumpRoutes: RTM_GETROUTE dump of all route tables, parsed into
//     netip.Prefix values for the cross-platform overlap decision in route.go.
//   - installOverlayRoute: RTM_NEWROUTE for one overlay prefix bound to the
//     profile interface (RTN_UNICAST, RT_TABLE_MAIN, RTPROT_STATIC), so kernel
//     routing steers overlay traffic into hubnet0.
//   - uninstallOverlayRoute: RTM_DELROUTE, used by rollback and Down.
//
// The adapter never installs a default route: only the frozen overlay prefixes
// from wireguard.go pass through installOverlayRoute (see OverlayRoutes).
//
// The framing helpers (rtmsg struct, buildRouteMessage, parseRouteDump) live
// here rather than netlink.go because they are Linux rtnetlink route-specific
// and never need to compile on non-Linux targets.

//go:build linux

package wireguard

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// rtmsg is the rtnetlink route message header (hand-rolled like ifinfomsg /
// ifaddrmsg in adapter_linux.go because x/sys does not export it). Layout per
// linux/rtnetlink.h: family, dst_len, src_len, tos, table, protocol, scope,
// type, flags(8) + reserved(3).
type rtmsg struct {
	Family   uint8
	DstLen   uint8
	SrcLen   uint8
	Tos      uint8
	Table    uint8
	Protocol uint8
	Scope    uint8
	Type     uint8
	Flags    uint8
	_        [3]uint8 // reserved
}

const sizeofRtmsg = int(unsafe.Sizeof(rtmsg{}))

// RouteEntry is one parsed route from an RTM_GETROUTE dump. The OIF lets the
// adapter distinguish its own leftover routes (bound to the profile interface)
// from routes another process owns — a crash that left the old interface and
// its routes in place must not brick the agent on restart.
type RouteEntry struct {
	Prefix netip.Prefix
	OIF    int32
}

// dumpRoutesLocked returns unicast routes from every routing table the kernel
// holds. The adapter uses the result as input to FindOverlayRouteConflict
// before installing its overlay routes. Policy-routing tables matter here:
// an ip rule can select one before the main table and shadow Hub's overlay
// routes. Local/multicast/kernel routes are not conflicts.
//
// Caller MUST hold a.mu: this method reuses the process netlink socket
// serialized by that mutex.
func (a *linuxAdapter) dumpRoutesLocked() ([]RouteEntry, error) {
	hdr := make([]byte, unix.NLMSG_HDRLEN+sizeofRtmsg)
	binary.LittleEndian.PutUint32(hdr, uint32(len(hdr)))
	binary.LittleEndian.PutUint16(hdr[4:], unix.RTM_GETROUTE)
	binary.LittleEndian.PutUint16(hdr[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	rm := rtmsg{Table: unix.RT_TABLE_UNSPEC}
	putRtmsg(hdr[unix.NLMSG_HDRLEN:], &rm)

	if err := a.sendRoute(hdr); err != nil {
		return nil, fmt.Errorf("wireguard: send route dump: %w", err)
	}
	var routes []RouteEntry
	for {
		chunk, done, err := a.recvDump()
		if err != nil {
			return nil, fmt.Errorf("wireguard: recv route dump: %w", err)
		}
		if chunk != nil {
			parsed, perr := parseRouteDump(chunk)
			if perr != nil {
				return nil, perr
			}
			routes = append(routes, parsed...)
		}
		if done {
			break
		}
	}
	return routes, nil
}

// recvDump reads one Recvfrom chunk from the netlink socket and classifies it
// as a payload message, the terminating NLMSG_DONE, or an error. Netlink
// DUMP replies arrive as multiple messages per chunk and end with NLMSG_DONE;
// the route dump loop keeps calling until done.
func (a *linuxAdapter) recvDump() (chunk []byte, done bool, err error) {
	tv := &unix.Timeval{Sec: netlinkRecvTimeoutSec}
	_ = unix.SetsockoptTimeval(a.routeFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, tv)
	buf := make([]byte, 65536)
	n, _, rerr := unix.Recvfrom(a.routeFD, buf, 0)
	if rerr != nil {
		return nil, false, rerr
	}
	if n < unix.NLMSG_HDRLEN {
		return nil, false, fmt.Errorf("wireguard: short dump reply %d", n)
	}
	// The first message type tells us whether the chunk is an ACK/DONE or a
	// data message. NLMSG_DONE marks the end of a dump.
	for _, msg := range splitMessages(buf[:n]) {
		msgType, _, _, _ := parseNlmsghdr(msg)
		if msgType == unix.NLMSG_DONE {
			return nil, true, nil
		}
		if msgType == unix.NLMSG_ERROR {
			if e := ackOrError(buf[:n]); e != nil {
				return nil, false, e
			}
		}
	}
	return append([]byte(nil), buf[:n]...), false, nil
}

// parseRouteDump walks one dump chunk and returns each route's destination
// prefix and output interface index. Non-unicast routes (local, broadcast,
// multicast, throw, blackhole) are skipped: they are not conflicts the agent
// would shadow.
func parseRouteDump(buf []byte) ([]RouteEntry, error) {
	var routes []RouteEntry
	for _, msg := range splitMessages(buf) {
		_, _, body, err := parseNlmsghdr(msg)
		if err != nil || len(body) < sizeofRtmsg {
			continue
		}
		rm := readRtmsg(body[:sizeofRtmsg])
		if rm.Type != unix.RTN_UNICAST {
			continue
		}
		entry, ok := parseRtmsgRoute(rm, body[sizeofRtmsg:])
		if ok {
			routes = append(routes, entry)
		}
	}
	return routes, nil
}

// parseRtmsgRoute decodes the destination prefix and output interface from a
// single rtmsg body. The destination is in RTA_DST; if absent the route is a
// default route (0/0 or ::/0) and its prefix length field carries 0. OIF
// comes from RTA_OIF.
func parseRtmsgRoute(rm rtmsg, attrs []byte) (RouteEntry, bool) {
	dst, family := netip.Addr{}, uint8(rm.Family)
	var oif int32
	r := newNlmsgReader(attrs, 0)
	for {
		at, payload, ok := r.Next()
		if !ok {
			break
		}
		switch at {
		case unix.RTA_DST:
			if len(payload) > 0 {
				dst = decodeRouteAddr(family, payload)
			}
		case unix.RTA_OIF:
			if len(payload) >= 4 {
				oif = int32(binary.LittleEndian.Uint32(payload))
			}
		}
	}
	prefixLen := int(rm.DstLen)
	if !dst.IsValid() {
		if family == unix.AF_INET {
			return RouteEntry{Prefix: netip.MustParsePrefix("0.0.0.0/0"), OIF: oif}, true
		}
		if family == unix.AF_INET6 {
			return RouteEntry{Prefix: netip.MustParsePrefix("::/0"), OIF: oif}, true
		}
		return RouteEntry{}, false
	}
	prefix, err := dst.Prefix(prefixLen)
	if err != nil {
		return RouteEntry{}, false
	}
	return RouteEntry{Prefix: prefix.Masked(), OIF: oif}, true
}

// decodeRouteAddr converts a raw netlink address payload into a netip.Addr of
// the correct family.
func decodeRouteAddr(family uint8, payload []byte) netip.Addr {
	if family == unix.AF_INET && len(payload) == 4 {
		return netip.AddrFrom4([4]byte{payload[0], payload[1], payload[2], payload[3]})
	}
	if family == unix.AF_INET6 && len(payload) == 16 {
		var b [16]byte
		copy(b[:], payload)
		return netip.AddrFrom16(b)
	}
	return netip.Addr{}
}

// installOverlayRouteLocked installs one overlay prefix route bound to ifIndex.
// The route is RTN_UNICAST in RT_TABLE_MAIN with protocol RTPROT_STATIC so it
// is attributable to the agent. NLM_F_REPLACE makes the install idempotent: a
// leftover route the previous agent process bound to the same interface is
// co-opted rather than treated as a foreign conflict. Used by Up after device
// configuration succeeds. Caller MUST hold a.mu.
func (a *linuxAdapter) installOverlayRouteLocked(prefix netip.Prefix, ifIndex int32) error {
	msg := buildRouteMessage(unix.RTM_NEWROUTE, prefix, ifIndex, unix.NLM_F_REPLACE)
	return a.sendRecvRouteAck(msg, fmt.Sprintf("install route %s", prefix))
}

// uninstallOverlayRouteLocked removes a previously installed overlay route.
// Errors are non-fatal: the interface teardown already drops routes that
// referenced it, so a missing route on rollback is the expected common case.
// Caller MUST hold a.mu.
func (a *linuxAdapter) uninstallOverlayRouteLocked(prefix netip.Prefix, ifIndex int32) error {
	msg := buildRouteMessage(unix.RTM_DELROUTE, prefix, ifIndex, 0)
	return a.sendRecvRouteAck(msg, fmt.Sprintf("uninstall route %s", prefix))
}

// existingOverlayRoutesLocked returns the dump entries that overlap the overlay
// prefixes, regardless of OIF. Used by Up's pre-check: routes bound to the
// profile interface (ownIndex) are leftovers the install path will co-opt, not
// conflicts; routes bound elsewhere or unbound are conflicts.
func (a *linuxAdapter) existingOverlayRoutesLocked(ownIndex int32) ([]RouteEntry, []netip.Prefix, error) {
	ownEntries, foreign := []RouteEntry{}, []netip.Prefix{}
	dump, err := a.dumpRoutesLocked()
	if err != nil {
		return nil, nil, err
	}
	for _, e := range dump {
		if !overlapsOverlaySpecifically(e.Prefix) {
			continue
		}
		if e.OIF == ownIndex {
			ownEntries = append(ownEntries, e)
			continue
		}
		foreign = append(foreign, e.Prefix)
	}
	return ownEntries, foreign, nil
}

// buildRouteMessage constructs an RTM_NEWROUTE / RTM_DELROUTE message. The
// route is unicast, main table, static protocol, bound to ifIndex, with
// destination = prefix. extraFlags ORs into the netlink flags (NLM_F_REPLACE
// for the idempotent install path; 0 for delete). NLM_F_EXCL is deliberately
// NOT set: EXCL and REPLACE are mutually exclusive in rtm_newroute (EXCL fails
// with EEXIST before REPLACE is considered), so a replace-style install would
// never actually replace an existing overlay route. A fresh route is created
// by NLM_F_CREATE; an existing one is co-opted by NLM_F_REPLACE.
func buildRouteMessage(msgType uint16, prefix netip.Prefix, ifIndex int32, extraFlags uint16) []byte {
	hdr := make([]byte, unix.NLMSG_HDRLEN+sizeofRtmsg)
	binary.LittleEndian.PutUint16(hdr[4:], msgType)
	binary.LittleEndian.PutUint16(hdr[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|extraFlags)
	var family uint8
	if prefix.Addr().Is4() {
		family = unix.AF_INET
	} else {
		family = unix.AF_INET6
	}
	rm := rtmsg{
		Family:   family,
		DstLen:   uint8(prefix.Bits()),
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	putRtmsg(hdr[unix.NLMSG_HDRLEN:], &rm)
	w := newNlmsgWriter(hdr)
	w.PutBytes(unix.RTA_DST, routeAddrBytes(prefix.Addr()))
	w.PutUint32(unix.RTA_OIF, uint32(ifIndex))
	return w.Bytes()
}

// routeAddrBytes returns the netlink payload for an RTA_DST address: the 4-byte
// IPv4 or 16-byte IPv6 form, no length prefix.
func routeAddrBytes(addr netip.Addr) []byte {
	if addr.Is4() {
		b4 := addr.As4()
		return b4[:]
	}
	b16 := addr.As16()
	return b16[:]
}

func putRtmsg(dst []byte, rm *rtmsg) {
	dst[0] = rm.Family
	dst[1] = rm.DstLen
	dst[2] = rm.SrcLen
	dst[3] = rm.Tos
	dst[4] = rm.Table
	dst[5] = rm.Protocol
	dst[6] = rm.Scope
	dst[7] = rm.Type
	dst[8] = rm.Flags
}

func readRtmsg(b []byte) rtmsg {
	return rtmsg{
		Family:   b[0],
		DstLen:   b[1],
		SrcLen:   b[2],
		Tos:      b[3],
		Table:    b[4],
		Protocol: b[5],
		Scope:    b[6],
		Type:     b[7],
		Flags:    b[8],
	}
}
