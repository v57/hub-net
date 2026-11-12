//go:build linux

package wireguard

import (
	"encoding/base64"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseDevicePeersReadsEachPeer(t *testing.T) {
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
	endpoint, err := endpointSockaddr("192.168.1.6:51820")
	if err != nil {
		t.Fatal(err)
	}
	w.PutBytes(unix.WGPEER_A_ENDPOINT, endpoint)
	w.CloseNested(first)
	second := w.PutNested(1)
	w.PutBytes(unix.WGPEER_A_PUBLIC_KEY, key(2))
	w.PutBytes(unix.WGPEER_A_LAST_HANDSHAKE_TIME, make([]byte, 16))
	w.CloseNested(second)
	w.CloseNested(peers)

	out := make(map[string]PeerStatus)
	parseDevicePeers(w.buf, out)
	firstPeer := out[base64.StdEncoding.EncodeToString(key(1))]
	if !firstPeer.LastHandshake.Equal(at) || firstPeer.Endpoint != netip.MustParseAddrPort("192.168.1.6:51820") {
		t.Fatalf("first peer = %+v, want the handshake at %v and endpoint 192.168.1.6:51820", firstPeer, at)
	}
	secondPeer, ok := out[base64.StdEncoding.EncodeToString(key(2))]
	if !ok || !secondPeer.LastHandshake.IsZero() || secondPeer.Endpoint.IsValid() {
		t.Fatalf("second peer = %+v (listed %v), want no handshake and no endpoint", secondPeer, ok)
	}
	if handshakes := lastHandshakes(out); len(handshakes) != 1 {
		t.Fatalf("handshakes = %v, want only the peer that had one", handshakes)
	}
}
