//go:build linux

package wireguard

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseDeviceHandshakesReadsEachPeer(t *testing.T) {
	key := func(b byte) []byte {
		out := make([]byte, 32)
		out[0] = b
		return out
	}
	timespec := func(at time.Time) []byte {
		out := make([]byte, 16)
		binary.NativeEndian.PutUint64(out[0:8], uint64(at.Unix()))
		binary.NativeEndian.PutUint64(out[8:16], uint64(at.Nanosecond()))
		return out
	}
	at := time.Unix(1_800_000_000, 5000)
	w := newNlmsgWriter(nil)
	w.PutString(unix.WGDEVICE_A_IFNAME, "hubnet0")
	peers := w.PutNested(unix.WGDEVICE_A_PEERS)
	first := w.PutNested(0)
	w.PutBytes(unix.WGPEER_A_PUBLIC_KEY, key(1))
	w.PutBytes(unix.WGPEER_A_LAST_HANDSHAKE_TIME, timespec(at))
	w.CloseNested(first)
	second := w.PutNested(1)
	w.PutBytes(unix.WGPEER_A_PUBLIC_KEY, key(2))
	w.PutBytes(unix.WGPEER_A_LAST_HANDSHAKE_TIME, make([]byte, 16))
	w.CloseNested(second)
	w.CloseNested(peers)

	out := make(map[string]time.Time)
	parseDeviceHandshakes(w.buf, out)
	if len(out) != 1 {
		t.Fatalf("handshakes = %v, want only the peer that had one", out)
	}
	if got := out[base64.StdEncoding.EncodeToString(key(1))]; !got.Equal(at) {
		t.Fatalf("handshake = %v, want %v", got, at)
	}
}
