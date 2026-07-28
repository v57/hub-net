package wireguard

import (
	"errors"
	"net/netip"
	"testing"
)

// TestNewPlatformAdapterReturnsAdapter guarantees the dispatch never returns
// nil — callers can rely on the returned Adapter being safe to call even on
// unsupported platforms (it will return ErrPlatformUnsupported).
func TestNewPlatformAdapterReturnsAdapter(t *testing.T) {
	a := NewPlatformAdapter("hubnet0")
	if a == nil {
		t.Fatal("NewPlatformAdapter returned nil")
	}
	// Every Adapter must be safe to query State on without prior Up; it just
	// reports down.
	if _, up := a.State(); up {
		t.Fatal("fresh adapter reports up")
	}
}

// TestPlatformUnsupportedAdapterFailsSafely asserts the non-Linux fallback
// path: every lifecycle method returns ErrPlatformUnsupported, and State never
// reports the interface as up. This is the network-agent spec "Unsupported
// platforms fail safely" requirement.
//
// On Linux the unsupportedAdapter type does not exist; the contract is
// exercised on non-Linux builds only.
func TestPlatformUnsupportedAdapterFailsSafely(t *testing.T) {
	a := newUnsupportedAdapterForTest(t)
	cfg := InterfaceConfig{Name: "hubnet0"}

	if err := a.Up(cfg); !errors.Is(err, ErrPlatformUnsupported) {
		t.Fatalf("Up err = %v, want ErrPlatformUnsupported", err)
	}
	if err := a.Down(); !errors.Is(err, ErrPlatformUnsupported) {
		t.Fatalf("Down err = %v, want ErrPlatformUnsupported", err)
	}
	if err := a.AddPeer(PeerConfig{}); !errors.Is(err, ErrPlatformUnsupported) {
		t.Fatalf("AddPeer err = %v, want ErrPlatformUnsupported", err)
	}
	if err := a.RemovePeer([]byte("k")); !errors.Is(err, ErrPlatformUnsupported) {
		t.Fatalf("RemovePeer err = %v, want ErrPlatformUnsupported", err)
	}
	if _, up := a.State(); up {
		t.Fatal("unsupportedAdapter reported up")
	}
}

// TestValidateAllowedIPsGateIsDeterministic re-asserts the gate the platform
// adapters run before touching netlink: it rejects default routes, non-overlay
// prefixes, and the reserved infrastructure range. This test runs on every
// platform because the gate is pure arithmetic over netip.Prefix.
func TestValidateAllowedIPsGateIsDeterministic(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		want   error
	}{
		{"default v4", "0.0.0.0/0", ErrDefaultRoute},
		{"default v6", "::/0", ErrDefaultRoute},
		{"outside overlay", "8.8.8.8/32", ErrForbiddenRoute},
		{"reserved infra", "100.127.255.5/32", ErrForbiddenRoute},
		{"in overlay v4", "100.96.0.5/32", nil},
		{"in overlay v6", "fd48:5542:4e45::5/128", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := netip.MustParsePrefix(tc.prefix)
			err := ValidateAllowedIPs([]netip.Prefix{p})
			if tc.want == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
