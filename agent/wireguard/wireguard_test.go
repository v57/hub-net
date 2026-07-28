package wireguard

import (
	"errors"
	"net/netip"
	"testing"
)

func TestValidateAllowedIPsRejectsDefaultRoute(t *testing.T) {
	v4Default := netip.MustParsePrefix("0.0.0.0/0")
	if err := ValidateAllowedIPs([]netip.Prefix{v4Default}); !errors.Is(err, ErrDefaultRoute) {
		t.Fatalf("err = %v, want ErrDefaultRoute", err)
	}
	v6Default := netip.MustParsePrefix("::/0")
	if err := ValidateAllowedIPs([]netip.Prefix{v6Default}); !errors.Is(err, ErrDefaultRoute) {
		t.Fatalf("err = %v, want ErrDefaultRoute", err)
	}
}

func TestValidateAllowedIPsRejectsOutsideOverlay(t *testing.T) {
	outside := netip.MustParsePrefix("8.8.8.8/32")
	err := ValidateAllowedIPs([]netip.Prefix{outside})
	if !errors.Is(err, ErrForbiddenRoute) {
		t.Fatalf("err = %v, want ErrForbiddenRoute", err)
	}
}

func TestValidateAllowedIPsRejectsReservedInfrastructure(t *testing.T) {
	reserved := netip.MustParsePrefix("100.127.255.5/32")
	err := ValidateAllowedIPs([]netip.Prefix{reserved})
	if !errors.Is(err, ErrForbiddenRoute) {
		t.Fatalf("err = %v, want ErrForbiddenRoute", err)
	}
}

func TestValidateAllowedIPsAcceptsOverlay(t *testing.T) {
	inOverlay := netip.MustParsePrefix("100.96.0.5/32")
	if err := ValidateAllowedIPs([]netip.Prefix{inOverlay}); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	v6 := netip.MustParsePrefix("fd48:5542:4e45::5/128")
	if err := ValidateAllowedIPs([]netip.Prefix{v6}); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

func TestFakeAdapterUpRejectsBadPeer(t *testing.T) {
	adapter := NewFakeAdapter()
	bad := PeerConfig{
		PublicKey: []byte("bad-peer-key-32-bytes-long-ok!!!"),
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
		},
	}
	if err := adapter.Up(InterfaceConfig{Name: "hubnet0", Peers: []PeerConfig{bad}}); !errors.Is(err, ErrDefaultRoute) {
		t.Fatalf("err = %v, want ErrDefaultRoute", err)
	}
}

func TestFakeAdapterPeerLifecycle(t *testing.T) {
	adapter := NewFakeAdapter()
	addr := netip.MustParseAddr("100.96.0.1")
	if err := adapter.Up(InterfaceConfig{Name: "hubnet0", Address: addr, ListenPort: DefaultPort}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	peer := PeerConfig{
		PublicKey:  []byte("peer-aaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")},
	}
	if err := adapter.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	state, ok := adapter.State()
	if !ok {
		t.Fatalf("State not up")
	}
	if len(state.Peers) != 1 {
		t.Fatalf("peer count = %d, want 1", len(state.Peers))
	}
	if err := adapter.RemovePeer(peer.PublicKey); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	state, _ = adapter.State()
	if len(state.Peers) != 0 {
		t.Fatalf("peer count after remove = %d, want 0", len(state.Peers))
	}
}

func TestFakeAdapterDownClearsState(t *testing.T) {
	adapter := NewFakeAdapter()
	if err := adapter.Up(InterfaceConfig{Name: "hubnet0"}); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := adapter.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if _, ok := adapter.State(); ok {
		t.Fatalf("State still up after Down")
	}
}
