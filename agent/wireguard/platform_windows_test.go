//go:build windows

package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func newUnsupportedAdapterForTest(t *testing.T) Adapter {
	t.Helper()
	t.Skip("Windows has the WireGuardNT adapter; see TestWindowsAdapterUpRejectsBadRoute")
	return nil
}

// The allowed-IP gate runs before the driver is touched, so this needs no
// privileges or wireguard.dll.
func TestWindowsAdapterUpRejectsBadRoute(t *testing.T) {
	a := newOSAdapter("hub-test0")
	bad := PeerConfig{
		PublicKey:  make([]byte, 32),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}
	if err := a.Up(InterfaceConfig{Name: "hub-test0", Peers: []PeerConfig{bad}}); !errors.Is(err, ErrDefaultRoute) {
		t.Fatalf("Up err = %v, want ErrDefaultRoute", err)
	}
	if _, up := a.State(); up {
		t.Fatal("adapter up after a rejected config")
	}
}

func TestAdapterGUIDIsStablePerName(t *testing.T) {
	if *adapterGUID("hubnet0") != *adapterGUID("hubnet0") {
		t.Fatal("GUID differs for the same name")
	}
	if *adapterGUID("hubnet0") == *adapterGUID("hubnet1") {
		t.Fatal("GUID equal for different names")
	}
}

// privileged skips unless the test runs elevated with HUBNET_WG_TEST=1 and
// wireguard.dll is loadable (next to the test binary).
func privileged(t *testing.T) {
	t.Helper()
	if os.Getenv("HUBNET_WG_TEST") != "1" {
		t.Skip("set HUBNET_WG_TEST=1 (elevated, wireguard.dll next to the test binary)")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("not elevated")
	}
	if err := ProbePlatformSupport(); err != nil {
		t.Fatalf("probe: %v", err)
	}
}

func keyPair(t *testing.T) (private, public []byte) {
	t.Helper()
	private = make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	private[0] &= 248
	private[31] = private[31]&127 | 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return private, public
}

func luidOf(t *testing.T, name string) (winipcfg.LUID, bool) {
	t.Helper()
	rows, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
	if err != nil {
		t.Fatal(err)
	}
	for i := range rows {
		if rows[i].Alias() == name {
			return rows[i].InterfaceLUID, true
		}
	}
	return 0, false
}

func hasOverlayRoute(t *testing.T, luid winipcfg.LUID) bool {
	t.Helper()
	_, err := luid.Route(IPv4OverlayPrefix, netip.IPv4Unspecified())
	return err == nil
}

// TestWindowsAdapterLifecycle brings two WireGuardNT adapters up in this
// process, peers them over loopback, waits for a handshake, then checks peer
// changes, routes and that Down removes the adapter with its routes.
func TestWindowsAdapterLifecycle(t *testing.T) {
	privileged(t)
	privA, pubA := keyPair(t)
	privB, pubB := keyPair(t)
	addrA := netip.MustParseAddr("100.96.250.1")
	addrB := netip.MustParseAddr("100.96.250.2")
	a := NewPlatformAdapter("hubnet-test-a")
	b := NewPlatformAdapter("hubnet-test-b")
	defer a.Down()
	defer b.Down()

	if err := a.Up(InterfaceConfig{
		Name: "hubnet-test-a", PrivateKey: privA, Address: addrA, ListenPort: 51901,
		AddressIPv6: netip.MustParseAddr("fd48:5542:4e45:fa::1"),
		Peers: []PeerConfig{{PublicKey: pubB, AllowedIPs: []netip.Prefix{netip.PrefixFrom(addrB, 32)},
			Endpoint: "127.0.0.1:51902", PersistentKeepalive: 1}},
	}); err != nil {
		t.Fatalf("Up a: %v", err)
	}
	// b's own overlay route would conflict with a's: the overlap check
	// refuses it, as on Linux.
	err := b.Up(InterfaceConfig{Name: "hubnet-test-b", PrivateKey: privB, Address: addrB, ListenPort: 51902})
	if !errors.Is(err, ErrOverlayRouteConflict) {
		t.Fatalf("Up b with a's overlay route present: err = %v, want ErrOverlayRouteConflict", err)
	}
	if _, ok := luidOf(t, "hubnet-test-b"); ok {
		t.Fatal("refused Up left adapter b behind")
	}

	luid, ok := luidOf(t, "hubnet-test-a")
	if !ok {
		t.Fatal("adapter a not found")
	}
	if !hasOverlayRoute(t, luid) {
		t.Fatal("overlay route missing on adapter a")
	}
	if _, err := luid.IPAddress(addrA); err != nil {
		t.Fatalf("address %s missing: %v", addrA, err)
	}
	row, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	if row.NLMTU != windowsMTU {
		t.Errorf("MTU = %d, want %d", row.NLMTU, windowsMTU)
	}

	// A second adapter object for the same name adopts it (a join's link).
	adopted := NewPlatformAdapter("hubnet-test-a")
	if err := adopted.Up(InterfaceConfig{
		Name: "hubnet-test-a", PrivateKey: privA, Address: addrA, ListenPort: 51901,
		Peers: []PeerConfig{{PublicKey: pubB, AllowedIPs: []netip.Prefix{netip.PrefixFrom(addrB, 32)},
			Endpoint: "127.0.0.1:51902", PersistentKeepalive: 1}},
	}); err != nil {
		t.Fatalf("adopting Up: %v", err)
	}

	// Handshake: a peer on the same machine whose own route can't coexist
	// with a's. A raw WireGuard responder isn't needed: b answers with no
	// routes of its own, through the low-level configuration.
	handle, _, err := openOrCreate("hubnet-test-b")
	if err != nil {
		t.Fatal(err)
	}
	if err := setConfiguration(handle.adapter, InterfaceConfig{PrivateKey: privB, ListenPort: 51902,
		Peers: []PeerConfig{{PublicKey: pubA, AllowedIPs: []netip.Prefix{netip.PrefixFrom(addrA, 32)}, Endpoint: "127.0.0.1:51901"}}}, true, false); err != nil {
		t.Fatal(err)
	}
	if err := handle.adapter.SetAdapterState(1); err != nil {
		t.Fatal(err)
	}
	reporter := adopted.(HandshakeReporter)
	deadline := time.Now().Add(15 * time.Second)
	for {
		handshakes, err := reporter.LastHandshakes()
		if err != nil {
			t.Fatal(err)
		}
		if len(handshakes) == 1 {
			for _, at := range handshakes {
				if time.Since(at) > time.Minute {
					t.Fatalf("handshake time %v is off", at)
				}
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no handshake between the two adapters")
		}
		time.Sleep(200 * time.Millisecond)
	}
	// WireGuardNT reports the endpoint it sends to b
	statuses, err := adopted.(PeerStatusReporter).PeerStatuses()
	if err != nil {
		t.Fatal(err)
	}
	if got := statuses[base64.StdEncoding.EncodeToString(pubB)].Endpoint; got != netip.MustParseAddrPort("127.0.0.1:51902") {
		t.Fatalf("endpoint of b = %v, want 127.0.0.1:51902", got)
	}
	_ = closeAdapter("hubnet-test-b")

	// Peers: add, update without endpoint, remove.
	_, pubC := keyPair(t)
	peerC := PeerConfig{PublicKey: pubC, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.250.3/32")}, Endpoint: "192.0.2.1:51820"}
	if err := adopted.AddPeer(peerC); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	peerC.Endpoint = ""
	if err := adopted.AddPeer(peerC); err != nil {
		t.Fatalf("AddPeer update: %v", err)
	}
	state, _ := adopted.State()
	if len(state.Peers) != 2 || state.Peers[1].Endpoint != "192.0.2.1:51820" {
		t.Fatalf("state peers = %+v", state.Peers)
	}
	if err := adopted.RemovePeer(pubC); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if err := adopted.AddPeer(PeerConfig{PublicKey: pubC, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}); !errors.Is(err, ErrDefaultRoute) {
		t.Fatalf("AddPeer default route err = %v", err)
	}

	if err := adopted.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	waitGone(t, "hubnet-test-a", luid)

	// Up again at once, as a restarted membership does: same name and GUID.
	again := NewPlatformAdapter("hubnet-test-a")
	if err := again.Up(InterfaceConfig{Name: "hubnet-test-a", PrivateKey: privA, Address: addrA, ListenPort: 51901}); err != nil {
		t.Fatalf("Up after Down: %v", err)
	}
	luid, ok = luidOf(t, "hubnet-test-a")
	if !ok || !hasOverlayRoute(t, luid) {
		t.Fatal("adapter or route missing after the second Up")
	}
	if err := again.Down(); err != nil {
		t.Fatalf("second Down: %v", err)
	}
	waitGone(t, "hubnet-test-a", luid)
}

// waitGone waits for Windows to remove a closed adapter and its routes, which
// it does shortly after the last handle closes.
func waitGone(t *testing.T, name string, luid winipcfg.LUID) {
	t.Helper()
	start := time.Now()
	for {
		_, present := luidOf(t, name)
		if !present && !hasOverlayRoute(t, luid) {
			t.Logf("%s gone %v after Down", name, time.Since(start).Round(time.Millisecond))
			return
		}
		if time.Since(start) > 15*time.Second {
			t.Fatalf("%s still present (adapter %v) 15s after Down", name, present)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
