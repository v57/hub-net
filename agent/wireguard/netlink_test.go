package wireguard

import (
	"encoding/binary"
	"testing"
)

// encodeGenlRequest builds a complete netlink request: nlmsghdr + genlmsghdr
// + attributes. Used by tests to assert byte-exact framing without a socket.
func encodeGenlRequest(msgType, familyID uint16, cmd, version uint8, body []byte) []byte {
	const nlmsgHdrLen = 16
	// Reserve nlmsghdr (16) + genlmsghdr (4).
	prologue := make([]byte, nlmsgHdrLen+genlmsghdrLen)
	binary.LittleEndian.PutUint16(prologue[4:], msgType)
	// Flags set by caller separately if needed; default REQUEST|ACK below.
	binary.LittleEndian.PutUint16(prologue[6:], 0x01|0x04)
	// genlmsghdr at offset 16.
	prologue[nlmsgHdrLen] = cmd
	prologue[nlmsgHdrLen+1] = version
	w := newNlmsgWriter(prologue)
	w.buf = append(w.buf, body...)
	return w.Bytes()
}

func TestNlmsgWriterBytesPatchesTotalLength(t *testing.T) {
	// 16-byte prologue + NLA(4-byte header + 2-byte uint16 = 6 -> padded to 8) = 24.
	const want = 24
	w := newNlmsgWriter(make([]byte, 16))
	w.PutUint16(0x01, 0x1234)
	got := w.Bytes()
	if len(got) != want {
		t.Fatalf("len = %d, want %d", len(got), want)
	}
	if total := binary.LittleEndian.Uint32(got[0:]); total != uint32(want) {
		t.Fatalf("nlmsghdr.Len = %d, want %d", total, want)
	}
}

func TestNlmsgWriterPutBytesAlignment(t *testing.T) {
	// 3-byte payload + 4-byte header = 7 -> padded to 8.
	const want = 16 + 8
	w := newNlmsgWriter(make([]byte, 16))
	w.PutBytes(0x42, []byte{0xaa, 0xbb, 0xcc})
	got := w.Bytes()
	if len(got) != want {
		t.Fatalf("len = %d, want %d (3-byte payload must pad to 8)", len(got), want)
	}
	// Padding bytes after the payload must be zero.
	if got[16+7] != 0 {
		t.Fatalf("padding byte = %02x, want 0", got[16+7])
	}
}

func TestNlmsgWriterPutStringAppendsNUL(t *testing.T) {
	// NLA: 4-byte header + 10 bytes ("wireguard" + NUL) = 14 -> padded to 16.
	const want = 16 + 16
	w := newNlmsgWriter(make([]byte, 16))
	w.PutString(0x02, "wireguard")
	got := w.Bytes()
	if len(got) != want {
		t.Fatalf("len = %d, want %d", len(got), want)
	}
	attrPayload := got[16+4 : 16+4+10]
	wantName := []byte("wireguard\x00")
	if string(attrPayload) != string(wantName) {
		t.Fatalf("payload = %q, want %q", attrPayload, wantName)
	}
}

func TestNlmsgReaderRoundTrip(t *testing.T) {
	w := newNlmsgWriter(make([]byte, 16)) // skip prologue in this test
	w.PutBytes(0x10, []byte{1, 2, 3})
	w.PutString(0x11, "hi")
	w.PutUint8(0x12, 0x07)
	w.PutUint16(0x13, 0xbeef)

	r := newNlmsgReader(w.Bytes(), 16)
	type out struct {
		typ uint16
		val []byte
	}
	var got []out
	for {
		at, payload, ok := r.Next()
		if !ok {
			break
		}
		got = append(got, out{at, payload})
	}
	if len(got) != 4 {
		t.Fatalf("attr count = %d, want 4", len(got))
	}
	if got[0].typ != 0x10 || string(got[0].val) != "\x01\x02\x03" {
		t.Fatalf("attr0 = {%.2x, %x}", got[0].typ, got[0].val)
	}
	// "hi" + NUL.
	if got[1].typ != 0x11 || string(got[1].val) != "hi\x00" {
		t.Fatalf("attr1 = {%.2x, %x}", got[1].typ, got[1].val)
	}
	if got[2].typ != 0x12 || len(got[2].val) != 1 || got[2].val[0] != 0x07 {
		t.Fatalf("attr2 = {%.2x, %x}", got[2].typ, got[2].val)
	}
	if got[3].typ != 0x13 {
		t.Fatalf("attr3 typ = %.2x, want 0x13", got[3].typ)
	}
	if v := binary.LittleEndian.Uint16(got[3].val); v != 0xbeef {
		t.Fatalf("attr3 val = %.4x, want beef", v)
	}
}

func TestNlmsgReaderNestedRoundTrip(t *testing.T) {
	// Build a WGDEVICE_A_PEERS nested attribute containing one peer with a
	// nested WGPEER_A_ALLOWEDIPS. Mirror the on-wire shape so the Linux
	// adapter's encode path and decode path stay symmetric.
	w := newNlmsgWriter(make([]byte, 16))

	deviceNested := w.PutNested(0x07)   // WGDEVICE_A_PEERS placeholder id for test
	peerNested := w.PutNested(0x07)     // WGPEER_A_ALLOWEDIPS placeholder
	w.PutBytes(0x01, []byte("peerkey")) // WGPEER_A_PUBLIC_KEY
	w.CloseNested(peerNested)
	w.CloseNested(deviceNested)
	buf := w.Bytes()

	// Walk: outer reader over the whole message body, then descend into nested.
	r := newNlmsgReader(buf, 16)
	outerType, outerPayload, ok := r.Next()
	if !ok || outerType&0x8000 == 0 {
		t.Fatalf("outer attr not nested: ok=%v type=%.4x", ok, outerType)
	}
	pr := newNlmsgReader(outerPayload, 0)
	peerType, peerPayload, ok := pr.Next()
	if !ok || peerType&0x8000 == 0 {
		t.Fatalf("peer attr not nested: ok=%v type=%.4x", ok, peerType)
	}
	// Inside the peer: the public key NLA.
	pp := newNlmsgReader(peerPayload, 0)
	keyType, keyPayload, ok := pp.Next()
	if !ok || keyType != 0x01 || string(keyPayload) != "peerkey" {
		t.Fatalf("public key NLA = {%.2x, %q}, want {01, peerkey}", keyType, keyPayload)
	}
	if _, _, more := pp.Next(); more {
		t.Fatalf("peer payload had more attributes than expected")
	}
}

func TestParseNlmsghdrTruncated(t *testing.T) {
	if _, _, _, err := parseNlmsghdr(make([]byte, 15)); err == nil {
		t.Fatalf("expected error for short buffer")
	}
	// Declared length longer than buffer.
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf, 64)
	if _, _, _, err := parseNlmsghdr(buf); err == nil {
		t.Fatalf("expected error for overlong declared length")
	}
}

func TestEncodeGenlRequestShape(t *testing.T) {
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	got := encodeGenlRequest(0x10, 0x20, 0x03 /*GETFAMILY*/, 0x01, body)
	// 16 (nlmsghdr) + 4 (genlmsghdr) + padded body (4 bytes -> 4) = 24.
	const want = 24
	if len(got) != want {
		t.Fatalf("len = %d, want %d", len(got), want)
	}
	msgType, _, body2, err := parseNlmsghdr(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msgType != 0x10 {
		t.Fatalf("msgType = %.2x", msgType)
	}
	cmd, ver, rest, err := parseGenlmsghdr(body2)
	if err != nil {
		t.Fatalf("genl parse: %v", err)
	}
	if cmd != 0x03 || ver != 0x01 {
		t.Fatalf("cmd/ver = %.2x/%.2x", cmd, ver)
	}
	if string(rest) != "\xde\xad\xbe\xef" {
		t.Fatalf("rest = %x", rest)
	}
}
