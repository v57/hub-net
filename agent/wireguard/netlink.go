// netlink.go provides minimal, allocation-conscious netlink message framing
// primitives used by the Linux WireGuard adapter (HN-303). The framing layer
// is pure Go with no Linux build constraint so the round-trip/encode tests in
// netlink_test.go can run on every platform without a netlink socket.
//
// Only the wireguard_linux.go adapter ever opens a real AF_NETLINK socket; the
// helpers here are the byte-level envelope (nlmsghdr + genlmsghdr + NLA TLV)
// shared between encode and decode paths. WireGuard attribute numbers
// (WGDEVICE_A_*, WGPEER_A_*, WGALLOWEDIP_A_*) and the genetlink control
// numbers (CTRL_CMD_GETFAMILY, CTRL_ATTR_FAMILY_ID) come from
// golang.org/x/sys/unix on Linux; here we re-declare the small subset used so
// the framing tests compile and pass on non-Linux platforms too.

package wireguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// nlaAlign rounds len up to the netlink TLV alignment (NLMSG_ALIGNTO = 4).
func nlaAlign(n int) int { return (n + 3) &^ 3 }

// nlaHeader is the netlink attribute header: 2-byte len (header + payload),
// 2-byte type. len includes the header itself.
type nlaHeader struct {
	Len  uint16
	Type uint16
}

// nlaHeaderLen is the size of an nlaHeader.
const nlaHeaderLen = 4

// nlmsgWriter builds a netlink message by appending TLV attributes. It owns no
// state beyond the backing buffer, so it is safe to discard after Bytes().
type nlmsgWriter struct {
	buf []byte
}

// newNlmsgWriter seeds the buffer with the fixed nlmsghdr + (optional)
// genlmsghdr prologue. Callers pass the already-encoded prologue; the writer
// only fills its length field in at the end via Finish.
func newNlmsgWriter(prologue []byte) *nlmsgWriter {
	return &nlmsgWriter{buf: append([]byte(nil), prologue...)}
}

// PutBytes appends an NLA with the given type and raw payload.
func (w *nlmsgWriter) PutBytes(attrType uint16, payload []byte) {
	totalLen := nlaHeaderLen + len(payload)
	padded := nlaAlign(totalLen)
	// Grow once; zero-fill padding tail.
	off := len(w.buf)
	w.buf = append(w.buf, make([]byte, padded)...)
	binary.LittleEndian.PutUint16(w.buf[off:], uint16(totalLen))
	binary.LittleEndian.PutUint16(w.buf[off+2:], attrType)
	copy(w.buf[off+nlaHeaderLen:], payload)
}

// PutUint8 appends an NLA carrying a single byte.
func (w *nlmsgWriter) PutUint8(attrType uint16, v uint8) {
	w.PutBytes(attrType, []byte{v})
}

// PutUint16 appends an NLA carrying a little-endian uint16.
func (w *nlmsgWriter) PutUint16(attrType uint16, v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	w.PutBytes(attrType, b[:])
}

// PutString appends an NLA carrying a NUL-terminated C string (the form
// genetlink expects for family names like "wireguard"). The trailing NUL is
// included in the payload.
func (w *nlmsgWriter) PutString(attrType uint16, s string) {
	payload := append(make([]byte, 0, len(s)+1), s...)
	payload = append(payload, 0)
	w.PutBytes(attrType, payload)
}

// PutNested opens a nested NLA. It appends the header with the nested flag and
// returns an offset the caller passes to CloseNested once children are added.
// The length field is patched in CloseNested.
func (w *nlmsgWriter) PutNested(attrType uint16) int {
	const nlaFNested = 0x8000
	off := len(w.buf)
	// Reserve an unpadded header; nested length is the exact child bytes,
	// padded as a whole by the enclosing alignment only at the very end.
	w.buf = append(w.buf, 0, 0, 0, 0)
	binary.LittleEndian.PutUint16(w.buf[off+2:], attrType|nlaFNested)
	return off
}

// CloseNested patches the length field of a nested attribute opened by
// PutNested to cover all child bytes written since.
func (w *nlmsgWriter) CloseNested(off int) {
	childLen := len(w.buf) - off
	binary.LittleEndian.PutUint16(w.buf[off:], uint16(childLen))
}

// Bytes finalizes the message. nlmsghdr.Len is patched to the full buffer size
// when the prologue was at least SizeofNlMsghdr (16) bytes; otherwise the
// buffer is returned as-is. The returned slice aliases the writer's storage —
// do not mutate.
func (w *nlmsgWriter) Bytes() []byte {
	const nlmsgHdrLen = 16
	if len(w.buf) >= nlmsgHdrLen {
		binary.LittleEndian.PutUint32(w.buf, uint32(len(w.buf)))
	}
	return w.buf
}

// nlmsgReader walks a netlink message buffer, yielding successive top-level
// attributes after a caller-specified header offset.
type nlmsgReader struct {
	buf []byte
	pos int
}

// newNlmsgReader returns a reader positioned just past the (nlmsghdr +
// genlmsghdr) header at the given offset.
func newNlmsgReader(buf []byte, attrOffset int) *nlmsgReader {
	return &nlmsgReader{buf: buf, pos: attrOffset}
}

// Next returns the next attribute's type and unpadded payload, or ok=false when
// no full attribute remains. Truncated headers are reported as ok=false.
func (r *nlmsgReader) Next() (attrType uint16, payload []byte, ok bool) {
	if r.pos+nlaHeaderLen > len(r.buf) {
		return 0, nil, false
	}
	totalLen := int(binary.LittleEndian.Uint16(r.buf[r.pos:]))
	if totalLen < nlaHeaderLen {
		return 0, nil, false
	}
	if r.pos+totalLen > len(r.buf) {
		return 0, nil, false
	}
	attrType = binary.LittleEndian.Uint16(r.buf[r.pos+2:])
	payload = r.buf[r.pos+nlaHeaderLen : r.pos+totalLen]
	// Advance past the padded attribute; clamp to buffer end so trailing
	// padding never reads out of bounds on the final attribute.
	r.pos += nlaAlign(totalLen)
	if r.pos > len(r.buf) {
		r.pos = len(r.buf)
	}
	return attrType, payload, true
}

// ErrTruncated signals a netlink message shorter than its declared length.
var ErrTruncated = errors.New("wireguard: netlink message truncated")

// parseNlmsghdr returns the type, flags, and the body (bytes after the 16-byte
// header). It does NOT validate semantics; callers check Type themselves.
func parseNlmsghdr(buf []byte) (msgType uint16, flags uint16, body []byte, err error) {
	const hdrLen = 16
	if len(buf) < hdrLen {
		return 0, 0, nil, fmt.Errorf("%w: have %d bytes, need %d", ErrTruncated, len(buf), hdrLen)
	}
	totalLen := binary.LittleEndian.Uint32(buf[0:])
	if int(totalLen) > len(buf) {
		return 0, 0, nil, fmt.Errorf("%w: declared %d, have %d", ErrTruncated, totalLen, len(buf))
	}
	msgType = binary.LittleEndian.Uint16(buf[4:])
	flags = binary.LittleEndian.Uint16(buf[6:])
	return msgType, flags, buf[hdrLen:int(totalLen)], nil
}

// genlmsghdrLen is Genlmsghdr size: cmd(1) + version(1) + reserved(2).
const genlmsghdrLen = 4

// parseGenlmsghdr returns cmd, version from the 4-byte genetlink header.
func parseGenlmsghdr(body []byte) (cmd uint8, version uint8, rest []byte, err error) {
	if len(body) < genlmsghdrLen {
		return 0, 0, nil, fmt.Errorf("%w: genlmsghdr need %d have %d", ErrTruncated, genlmsghdrLen, len(body))
	}
	return body[0], body[1], body[genlmsghdrLen:], nil
}

// Address family numbers in the sockaddr WGPEER_A_ENDPOINT carries (Linux).
const (
	sockaddrFamilyInet4 = 2
	sockaddrFamilyInet6 = 10
)

// endpointSockaddr encodes a peer endpoint ("ip:port") as the struct
// sockaddr_in / sockaddr_in6 the kernel expects in WGPEER_A_ENDPOINT. Sending
// the endpoint as text leaves the peer without an endpoint, so it can never
// start a handshake.
func endpointSockaddr(endpoint string) ([]byte, error) {
	addrPort, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("wireguard: endpoint %q: %w", endpoint, err)
	}
	addr := addrPort.Addr().Unmap()
	if addr.Is4() {
		// sockaddr_in: family, port (network order), address, 8 bytes padding.
		out := make([]byte, 16)
		binary.NativeEndian.PutUint16(out[0:2], sockaddrFamilyInet4)
		binary.BigEndian.PutUint16(out[2:4], addrPort.Port())
		ip := addr.As4()
		copy(out[4:8], ip[:])
		return out, nil
	}
	// sockaddr_in6: family, port, flowinfo, address, scope id.
	out := make([]byte, 28)
	binary.NativeEndian.PutUint16(out[0:2], sockaddrFamilyInet6)
	binary.BigEndian.PutUint16(out[2:4], addrPort.Port())
	ip := addr.As16()
	copy(out[8:24], ip[:])
	return out, nil
}

// validateEndpoints rejects peer endpoints that are not "ip:port" literals.
func validateEndpoints(peers ...PeerConfig) error {
	for _, peer := range peers {
		if peer.Endpoint == "" {
			continue
		}
		if _, err := endpointSockaddr(peer.Endpoint); err != nil {
			return err
		}
	}
	return nil
}
