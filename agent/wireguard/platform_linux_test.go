//go:build linux

package wireguard

import (
	"errors"
	"net/netip"
	"testing"
)

// On Linux the unsupportedAdapter type is absent. The unsupported-platform
// contract is exercised by the OS-agnostic platform_other.go on non-Linux
// builds; here we instead assert the deterministic ValidateAllowedIPs gate
// runs in linuxAdapter.Up before any netlink call, so the test stays
// meaningful on Linux without privileges.
func newUnsupportedAdapterForTest(t *testing.T) Adapter {
	t.Helper()
	t.Skip("unsupportedAdapter type only exists on non-Linux builds; see TestLinuxAdapterUpRejectsBadRoute for the Linux gate")
	return nil
}

// TestLinuxAdapterUpRejectsBadRoute verifies the deterministic gate:
// linuxAdapter.Up rejects a peer with a default-route AllowedIP before ever
// opening a netlink socket. This runs without CAP_NET_ADMIN because the
// validation is pure arithmetic.
func TestLinuxAdapterUpRejectsBadRoute(t *testing.T) {
	a := newOSAdapter("hub-test0").(*linuxAdapter)
	bad := PeerConfig{
		PublicKey:  []byte("peer-aaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}
	err := a.Up(InterfaceConfig{Name: "hub-test0", Peers: []PeerConfig{bad}})
	if !errors.Is(err, ErrDefaultRoute) {
		t.Fatalf("Up err = %v, want ErrDefaultRoute", err)
	}
}
