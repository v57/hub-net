// adapter_linux_test.go covers the Linux adapter's deterministic,
// privilege-free surface: the encoded SET_DEVICE byte shape and the
// ValidateAllowedIPs gate in Up/AddPeer. Real-device lifecycle tests are
// gated behind HUB_NET_WG_DEVICE so CI without root/CAP_NET_ADMIN skips
// cleanly.

//go:build linux

package wireguard

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestEncodeSetDeviceShape asserts the exact WG_CMD_SET_DEVICE payload the
// adapter produces for a full Up: IFNAME + PRIVATE_KEY + LISTEN_PORT +
// FLAGS(REPLACE_PEERS) + PEERS(nested, one peer with PUBLIC_KEY + ALLOWEDIPS +
// REPLACE_ALLOWEDIPS). This is the byte-level contract the kernel WireGuard
// module expects; pinning it here catches regressions in the framing helpers
// without needing a kernel.
func TestEncodeSetDeviceShape(t *testing.T) {
	a := &linuxAdapter{name: "hub-test0", familyID: 0x1a}
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	peerKey := []byte("peer-aaaaaaaaaaaaaaaaaaaaaaaaaaa") // 31 bytes -> pad to 32 in payload
	cfg := InterfaceConfig{
		Name:       "hub-test0",
		PrivateKey: priv,
		ListenPort: 51820,
		Peers: []PeerConfig{{
			PublicKey:  peerKey,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.0.5/32")},
		}},
	}

	body := a.encodeSetDevice(cfg, true /*replacePeers*/, false /*removePeer*/)

	// Header sanity: type=familyID, flags=REQUEST|ACK, cmd=SET_DEVICE.
	if got := binary.LittleEndian.Uint16(body[4:]); got != 0x1a {
		t.Fatalf("nlmsg type = %.4x, want 1a", got)
	}
	if got := binary.LittleEndian.Uint16(body[6:]); got != unix.NLM_F_REQUEST|unix.NLM_F_ACK {
		t.Fatalf("nlmsg flags = %.4x", got)
	}
	if cmd := body[unix.NLMSG_HDRLEN]; cmd != byte(unix.WG_CMD_SET_DEVICE) {
		t.Fatalf("genl cmd = %.2x, want SET_DEVICE", cmd)
	}

	// Walk top-level WGDEVICE attributes; collect their types.
	r := newNlmsgReader(body, unix.NLMSG_HDRLEN+genlmsghdrLen)
	var seen []uint16
	var peersPayload []byte
	for {
		at, payload, ok := r.Next()
		if !ok {
			break
		}
		baseType := at & 0x3fff
		seen = append(seen, baseType)
		if baseType == unix.WGDEVICE_A_PEERS {
			peersPayload = payload
		}
		// Spot-check IFNAME carries the NUL-terminated name.
		if baseType == unix.WGDEVICE_A_IFNAME {
			name := string(payload[:len(payload)-1]) // strip trailing NUL
			if name != "hub-test0" {
				t.Fatalf("ifname = %q", name)
			}
		}
		if baseType == unix.WGDEVICE_A_FLAGS {
			if v := binary.LittleEndian.Uint32(payload); v != unix.WGDEVICE_F_REPLACE_PEERS {
				t.Fatalf("device flags = %.8x, want REPLACE_PEERS", v)
			}
		}
	}
	wantAttrs := map[uint16]string{
		unix.WGDEVICE_A_IFNAME:      "IFNAME",
		unix.WGDEVICE_A_PRIVATE_KEY: "PRIVATE_KEY",
		unix.WGDEVICE_A_LISTEN_PORT: "LISTEN_PORT",
		unix.WGDEVICE_A_FLAGS:       "FLAGS",
		unix.WGDEVICE_A_PEERS:       "PEERS",
	}
	for want, name := range wantAttrs {
		found := false
		for _, got := range seen {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing WGDEVICE_A_%s in %v", name, seen)
		}
	}

	// Descend into the single peer: PUBLIC_KEY + ALLOWEDIPS + FLAGS.
	if peersPayload == nil {
		t.Fatal("PEERS payload absent")
	}
	pr := newNlmsgReader(peersPayload, 0)
	peerType, peerPayload, ok := pr.Next()
	if !ok || peerType&0x8000 == 0 {
		t.Fatalf("peer not nested: %.4x", peerType)
	}
	pp := newNlmsgReader(peerPayload, 0)
	var peerSeen []uint16
	for {
		at, _, ok := pp.Next()
		if !ok {
			break
		}
		peerSeen = append(peerSeen, at&0x3fff)
	}
	for _, want := range []uint16{
		unix.WGPEER_A_PUBLIC_KEY,
		unix.WGPEER_A_ALLOWEDIPS,
		unix.WGPEER_A_FLAGS,
	} {
		found := false
		for _, got := range peerSeen {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("peer missing attr %.4x in %v", want, peerSeen)
		}
	}
}

// TestEncodeSetDeviceRemovePeerShape asserts the RemovePeer path encodes a
// peer carrying only PUBLIC_KEY + FLAGS(WGPEER_F_REMOVE_ME), no ALLOWEDIPS.
func TestEncodeSetDeviceRemovePeerShape(t *testing.T) {
	a := &linuxAdapter{name: "hub-test0", familyID: 0x1a}
	peerKey := []byte("peer-aaaaaaaaaaaaaaaaaaaaaaaaaaa")
	cfg := InterfaceConfig{
		Name:  "hub-test0",
		Peers: []PeerConfig{{PublicKey: peerKey}},
	}
	body := a.encodeSetDevice(cfg, false /*replacePeers*/, true /*removePeer*/)

	r := newNlmsgReader(body, unix.NLMSG_HDRLEN+genlmsghdrLen)
	var peersPayload []byte
	for {
		at, payload, ok := r.Next()
		if !ok {
			break
		}
		baseType := at & 0x3fff
		if baseType == unix.WGDEVICE_A_FLAGS {
			t.Fatalf("removePeer path must NOT set WGDEVICE_F_REPLACE_PEERS")
		}
		if baseType == unix.WGDEVICE_A_PEERS {
			peersPayload = payload
		}
	}
	if peersPayload == nil {
		t.Fatal("PEERS absent")
	}
	pr := newNlmsgReader(peersPayload, 0)
	_, peerPayload, ok := pr.Next()
	if !ok {
		t.Fatal("peer absent")
	}
	pp := newNlmsgReader(peerPayload, 0)
	var sawAllowedIPs, sawRemoveFlag bool
	for {
		at, payload, ok := pp.Next()
		if !ok {
			break
		}
		baseType := at & 0x3fff
		if baseType == unix.WGPEER_A_ALLOWEDIPS {
			sawAllowedIPs = true
		}
		if baseType == unix.WGPEER_A_FLAGS && len(payload) >= 4 {
			if v := binary.LittleEndian.Uint32(payload); v == unix.WGPEER_F_REMOVE_ME {
				sawRemoveFlag = true
			}
		}
	}
	if sawAllowedIPs {
		t.Fatal("removePeer peer must not carry ALLOWEDIPS")
	}
	if !sawRemoveFlag {
		t.Fatal("removePeer peer missing WGPEER_F_REMOVE_ME")
	}
}

// TestLinuxAdapterAddPeerRejectsBadRoute mirrors the Up gate on AddPeer.
func TestLinuxAdapterAddPeerRejectsBadRoute(t *testing.T) {
	a := &linuxAdapter{name: "hub-test0", up: true}
	bad := PeerConfig{
		PublicKey:  []byte("peer-aaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")},
	}
	err := a.AddPeer(bad)
	if !errors.Is(err, ErrForbiddenRoute) {
		t.Fatalf("AddPeer err = %v, want ErrForbiddenRoute", err)
	}
}

// TestBuildRouteMessageShape pins the RTM_NEWROUTE payload the adapter installs
// for an overlay prefix: rtmsg header (family/dst_len/table=MAIN/protocol=
// STATIC/scope=UNIVERSE/type=UNICAST) + RTA_DST + RTA_OIF + NLM_F_REPLACE.
// This is the byte-level contract the kernel rtnetlink expects; pinning it
// here catches regressions in the route framing without needing privileges.
func TestBuildRouteMessageShape(t *testing.T) {
	msg := buildRouteMessage(unix.RTM_NEWROUTE, IPv4OverlayPrefix, 42, unix.NLM_F_REPLACE)

	msgType, flags, body, err := parseNlmsghdr(msg)
	if err != nil {
		t.Fatalf("parseNlmsghdr: %v", err)
	}
	if msgType != unix.RTM_NEWROUTE {
		t.Fatalf("msgType = %.4x, want NEWROUTE", msgType)
	}
	// NLM_F_EXCL must not be set: combined with NLM_F_REPLACE the kernel
	// rejects every replace of an existing route with EEXIST.
	if flags != unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE {
		t.Fatalf("flags = %.4x", flags)
	}
	rm := readRtmsg(body[:sizeofRtmsg])
	if rm.Family != unix.AF_INET {
		t.Fatalf("family = %d, want AF_INET", rm.Family)
	}
	if rm.DstLen != uint8(IPv4OverlayPrefix.Bits()) {
		t.Fatalf("dstLen = %d, want %d", rm.DstLen, IPv4OverlayPrefix.Bits())
	}
	if rm.Table != unix.RT_TABLE_MAIN {
		t.Fatalf("table = %d, want MAIN", rm.Table)
	}
	if rm.Protocol != unix.RTPROT_STATIC {
		t.Fatalf("protocol = %d, want STATIC", rm.Protocol)
	}
	if rm.Type != unix.RTN_UNICAST {
		t.Fatalf("type = %d, want UNICAST", rm.Type)
	}

	// Walk attributes: RTA_DST carries the prefix network address, RTA_OIF
	// carries the interface index.
	r := newNlmsgReader(body, sizeofRtmsg)
	var sawDst, sawOIF bool
	for {
		at, payload, ok := r.Next()
		if !ok {
			break
		}
		switch at {
		case unix.RTA_DST:
			sawDst = true
			if got := decodeRouteAddr(unix.AF_INET, payload); got != IPv4OverlayPrefix.Addr() {
				t.Fatalf("RTA_DST = %s, want %s", got, IPv4OverlayPrefix.Addr())
			}
		case unix.RTA_OIF:
			sawOIF = true
			if len(payload) < 4 {
				t.Fatalf("RTA_OIF payload short: %d", len(payload))
			}
			if got := binary.LittleEndian.Uint32(payload); got != 42 {
				t.Fatalf("RTA_OIF = %d, want 42", got)
			}
		}
	}
	if !sawDst {
		t.Fatal("RTA_DST absent")
	}
	if !sawOIF {
		t.Fatal("RTA_OIF absent")
	}
}

// TestBuildRouteMessageV6Shape mirrors the v4 shape test for an IPv6 overlay
// prefix: family AF_INET6, 16-byte RTA_DST.
func TestBuildRouteMessageV6Shape(t *testing.T) {
	msg := buildRouteMessage(unix.RTM_NEWROUTE, IPv6OverlayPrefix, 7, 0)
	_, _, body, err := parseNlmsghdr(msg)
	if err != nil {
		t.Fatalf("parseNlmsghdr: %v", err)
	}
	rm := readRtmsg(body[:sizeofRtmsg])
	if rm.Family != unix.AF_INET6 {
		t.Fatalf("family = %d, want AF_INET6", rm.Family)
	}
	if rm.DstLen != uint8(IPv6OverlayPrefix.Bits()) {
		t.Fatalf("dstLen = %d, want %d", rm.DstLen, IPv6OverlayPrefix.Bits())
	}
	r := newNlmsgReader(body, sizeofRtmsg)
	for {
		at, payload, ok := r.Next()
		if !ok {
			t.Fatal("RTA_DST absent")
		}
		if at == unix.RTA_DST {
			if got := decodeRouteAddr(unix.AF_INET6, payload); got != IPv6OverlayPrefix.Addr() {
				t.Fatalf("RTA_DST = %s, want %s", got, IPv6OverlayPrefix.Addr())
			}
			return
		}
	}
}

// TestParseRouteDumpRoundTrip builds a synthetic dump chunk with one route and
// asserts parseRouteDump recovers the prefix and OIF. This pins the decode
// path the adapter runs against a real GETROUTE reply.
func TestParseRouteDumpRoundTrip(t *testing.T) {
	dst := netip.MustParsePrefix("100.100.0.0/16")
	ifIndex := int32(11)
	// Build an RTM_NEWROUTE message with the prefix, then wrap it as a dump
	// chunk parseRouteDump can read.
	one := buildRouteMessage(unix.RTM_NEWROUTE, dst, ifIndex, 0)
	// Patch the message length field to the actual buffer size; buildRouteMessage
	// already did this via nlmsgWriter.Bytes, but the dump chunk is a single
	// concatenated message and parseRouteDump walks it via splitMessages.
	chunk := one
	entries, err := parseRouteDump(chunk)
	if err != nil {
		t.Fatalf("parseRouteDump: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Prefix != dst {
		t.Fatalf("prefix = %s, want %s", entries[0].Prefix, dst)
	}
	if entries[0].OIF != ifIndex {
		t.Fatalf("OIF = %d, want %d", entries[0].OIF, ifIndex)
	}
}

// TestParseRouteDumpSkipsNonUnicast ensures the dump parser ignores local,
// broadcast, and other non-unicast routes: they are not conflicts the agent
// would shadow.
func TestParseRouteDumpSkipsNonUnicast(t *testing.T) {
	// Hand-build a route message whose rtmsg.Type is RTN_LOCAL (not UNICAST).
	hdr := make([]byte, unix.NLMSG_HDRLEN+sizeofRtmsg)
	binary.LittleEndian.PutUint16(hdr[4:], unix.RTM_NEWROUTE)
	binary.LittleEndian.PutUint16(hdr[6:], unix.NLM_F_REQUEST)
	rm := rtmsg{Family: unix.AF_INET, DstLen: 32, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_LOCAL}
	putRtmsg(hdr[unix.NLMSG_HDRLEN:], &rm)
	// Patch total length.
	binary.LittleEndian.PutUint32(hdr, uint32(len(hdr)))
	entries, err := parseRouteDump(hdr)
	if err != nil {
		t.Fatalf("parseRouteDump: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("len(entries) = %d, want 0 (local route skipped)", len(entries))
	}
}

// TestLinuxAdapterLifecycle exercises a real kernel WireGuard interface when
// HUB_NET_WG_DEVICE names a scratch interface and the test runs as root.
// Otherwise it skips: CI without CAP_NET_ADMIN stays green. The HN-304
// extension asserts the overlay routes are installed on Up and gone on Down.
func TestLinuxAdapterLifecycle(t *testing.T) {
	name := os.Getenv("HUB_NET_WG_DEVICE")
	if name == "" {
		t.Skip("set HUB_NET_WG_DEVICE=<ifname> and run as root to exercise real kernel WG")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN)")
	}

	a := newOSAdapter(name).(*linuxAdapter)
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	cfg := InterfaceConfig{
		Name:       name,
		PrivateKey: priv,
		ListenPort: 51820,
		Address:    netip.MustParseAddr("100.96.0.1"),
	}
	if err := a.Up(cfg); err != nil {
		t.Fatalf("Up: %v", err)
	}
	t.Cleanup(func() { _ = a.Down() })

	// HN-304: dump the table and confirm both overlay routes are present,
	// bound to this interface. The agent's own self-route for 100.96.0.1 is
	// also expected and must not be reported as a conflict.
	idx, err := a.ifIndexLocked(name)
	if err != nil {
		t.Fatalf("ifindex: %v", err)
	}
	entries, err := a.dumpRoutesLocked()
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	have := make(map[string]bool, len(entries))
	for _, e := range entries {
		have[e.Prefix.String()] = true
	}
	for _, want := range OverlayRoutes() {
		if !have[want.String()] {
			t.Fatalf("overlay route %s not in route table after Up", want)
		}
	}
	// The agent's installed overlay routes are equal-prefix unicast routes;
	// verify they are bound to this interface (OIF == idx) so the
	// own-vs-foreign filter would correctly co-opt them on restart.
	for _, want := range OverlayRoutes() {
		found := false
		for _, e := range entries {
			if e.Prefix == want && e.OIF == idx {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("overlay route %s not bound to ifindex %d", want, idx)
		}
	}
	// A re-run conflict check with the agent's self-address must still be
	// clean when own-routes are filtered by OIF: extract the foreign subset
	// and confirm no false positive.
	foreignPrefixes := []netip.Prefix{}
	for _, e := range entries {
		if overlapsOverlaySpecifically(e.Prefix) && e.OIF != idx {
			foreignPrefixes = append(foreignPrefixes, e.Prefix)
		}
	}
	if conflict, ok := FindOverlayRouteConflict(foreignPrefixes, cfg.Address); ok {
		t.Fatalf("own overlay routes reported as conflict (%s); OIF filter broke", conflict)
	}

	state, up := a.State()
	if !up {
		t.Fatal("State not up after Up")
	}
	if state.Name != name {
		t.Fatalf("state.Name = %q, want %q", state.Name, name)
	}
	if state.ListenPort != 51820 {
		t.Fatalf("state.ListenPort = %d", state.ListenPort)
	}

	peer := PeerConfig{
		PublicKey:  make([]byte, 32),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")},
	}
	for i := range peer.PublicKey {
		peer.PublicKey[i] = byte(0xa0 + i)
	}
	if err := a.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := a.RemovePeer(peer.PublicKey); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}

	// HN-304: Down removes the overlay routes. Re-dump (socket is still open
	// before Down closes it) by querying through a fresh adapter state would
	// be racy; instead assert the routes are absent via a clean dump after
	// Down re-opens its own socket.
	if err := a.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	probe := newOSAdapter(name).(*linuxAdapter)
	if err := probeUpSocket(probe); err != nil {
		t.Skipf("cannot reopen netlink for post-Down probe: %v", err)
	}
	afterEntries, err := probe.dumpRoutesLocked()
	if err != nil {
		t.Skipf("post-Down dump failed: %v", err)
	}
	after := make([]netip.Prefix, 0, len(afterEntries))
	for _, e := range afterEntries {
		after = append(after, e.Prefix)
	}
	for _, want := range OverlayRoutes() {
		for _, got := range after {
			if got == want {
				t.Fatalf("overlay route %s still present after Down", want)
			}
		}
	}
}

// TestLinuxAdapterRejectsLiveRouteConflict exercises policy-routing tables as
// well as the main table. It creates no interface because conflict detection
// runs before link mutation.
func TestLinuxAdapterRejectsLiveRouteConflict(t *testing.T) {
	name := os.Getenv("HUB_NET_WG_CONFLICT_DEVICE")
	if name == "" {
		t.Skip("set HUB_NET_WG_CONFLICT_DEVICE=<unused-ifname> on a host with an overlay route conflict")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN)")
	}

	a := newOSAdapter(name).(*linuxAdapter)
	err := a.Up(InterfaceConfig{
		Name:       name,
		PrivateKey: make([]byte, 32),
		ListenPort: 51820,
		Address:    netip.MustParseAddr("100.96.0.1"),
	})
	if !errors.Is(err, ErrOverlayRouteConflict) {
		if err == nil {
			_ = a.Down()
		}
		t.Fatalf("Up error = %v, want ErrOverlayRouteConflict", err)
	}
}

// probeUpSocket opens the netlink socket on a fresh adapter just enough to run
// a route dump. Used by TestLinuxAdapterLifecycle to verify Down cleaned up.
func probeUpSocket(a *linuxAdapter) error {
	fd, err := openNetlinkSocket()
	if err != nil {
		return err
	}
	a.fd = fd
	routeFD, err := openRouteNetlinkSocket()
	if err != nil {
		_ = unix.Close(fd)
		return err
	}
	a.routeFD = routeFD
	fid, err := a.resolveFamily()
	if err != nil {
		return err
	}
	a.familyID = fid
	return nil
}

// TestRoutePreferredSource pins RTA_PREFSRC on an overlay route: members keep
// a temporary bootstrap address on the interface, and overlay traffic must use
// the permanent one.
func TestRoutePreferredSource(t *testing.T) {
	source := netip.MustParseAddr("100.96.0.2")
	msg := appendRouteAttr(buildRouteMessage(unix.RTM_NEWROUTE, IPv4OverlayPrefix, 42, unix.NLM_F_REPLACE), unix.RTA_PREFSRC, routeAddrBytes(source))
	_, _, body, err := parseNlmsghdr(msg)
	if err != nil {
		t.Fatalf("parseNlmsghdr: %v", err)
	}
	if got := binary.LittleEndian.Uint32(msg); int(got) != len(msg) {
		t.Fatalf("nlmsg length = %d, want %d", got, len(msg))
	}
	r := newNlmsgReader(body, sizeofRtmsg)
	for {
		at, payload, ok := r.Next()
		if !ok {
			break
		}
		if at == unix.RTA_PREFSRC {
			if got := decodeRouteAddr(unix.AF_INET, payload); got != source {
				t.Fatalf("RTA_PREFSRC = %s, want %s", got, source)
			}
			return
		}
	}
	t.Fatal("RTA_PREFSRC missing")
}
