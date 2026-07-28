// route_test.go covers the cross-platform HN-304 primitives: the overlay
// route set and the overlap decision. Both are pure arithmetic over
// netip.Prefix, so the tests run on every platform without privileges.

package wireguard

import (
	"net/netip"
	"testing"
)

// TestOverlayRoutesCoversOverlayAndExcludesDefault pins the route set the
// adapter installs: exactly the two overlay prefixes, neither a default route.
func TestOverlayRoutesCoversOverlayAndExcludesDefault(t *testing.T) {
	routes := OverlayRoutes()
	if len(routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(routes))
	}
	for _, r := range routes {
		if r.Bits() == 0 {
			t.Fatalf("overlay route %s is a default route", r)
		}
		if !r.Overlaps(IPv4OverlayPrefix) && !r.Overlaps(IPv6OverlayPrefix) {
			t.Fatalf("overlay route %s is outside the overlay prefixes", r)
		}
	}
}

// TestFindOverlayRouteConflict enumerates the overlap decision. The agent
// fails closed on any pre-existing route into the overlay except its own
// self-route (a stale /32 from a prior run is harmless).
func TestFindOverlayRouteConflict(t *testing.T) {
	v4Self := netip.MustParseAddr("100.96.0.1")
	v6Self := netip.MustParseAddr("fd48:5542:4e45::1")
	cases := []struct {
		name      string
		existing  []netip.Prefix
		selfAddrs []netip.Addr
		wantHit   bool
	}{
		{
			name:      "empty table",
			existing:  nil,
			selfAddrs: []netip.Addr{v4Self},
			wantHit:   false,
		},
		{
			name: "default route does not overlap",
			existing: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
			},
			selfAddrs: []netip.Addr{v4Self},
			wantHit:   false,
		},
		{
			name: "default v6 route does not overlap",
			existing: []netip.Prefix{
				netip.MustParsePrefix("::/0"),
			},
			selfAddrs: []netip.Addr{v4Self},
			wantHit:   false,
		},
		{
			name: "unrelated public route",
			existing: []netip.Prefix{
				netip.MustParsePrefix("8.8.8.0/24"),
			},
			selfAddrs: []netip.Addr{v4Self},
			wantHit:   false,
		},
		{
			name: "broader cgnat range does not overlap (overlay more specific)",
			existing: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.0/10"),
			},
			selfAddrs: []netip.Addr{v4Self},
			wantHit:   false,
		},
		{
			name: "equal overlay prefix conflicts",
			existing: []netip.Prefix{
				netip.MustParsePrefix("100.96.0.0/11"),
			},
			selfAddrs: []netip.Addr{v4Self},
			wantHit:   true,
		},
		{
			name: "more specific inside overlay conflicts",
			existing: []netip.Prefix{
				netip.MustParsePrefix("100.100.0.0/16"),
			},
			selfAddrs: []netip.Addr{v4Self},
			wantHit:   true,
		},
		{
			name: "reserved infrastructure conflicts",
			existing: []netip.Prefix{
				netip.MustParsePrefix("100.127.255.0/24"),
			},
			selfAddrs: []netip.Addr{v4Self},
			wantHit:   true,
		},
		{
			name: "self-route v4 ignored",
			existing: []netip.Prefix{
				netip.MustParsePrefix("100.96.0.1/32"),
			},
			selfAddrs: []netip.Addr{v4Self},
			wantHit:   false,
		},
		{
			name: "self-route v6 ignored",
			existing: []netip.Prefix{
				netip.MustParsePrefix("fd48:5542:4e45::1/128"),
			},
			selfAddrs: []netip.Addr{v6Self},
			wantHit:   false,
		},
		{
			name: "v6 route inside overlay conflicts",
			existing: []netip.Prefix{
				netip.MustParsePrefix("fd48:5542:4e45:dead::/64"),
			},
			selfAddrs: []netip.Addr{v6Self},
			wantHit:   true,
		},
		{
			name: "stale self-route for unassigned overlay addr conflicts",
			existing: []netip.Prefix{
				netip.MustParsePrefix("100.96.0.99/32"),
			},
			selfAddrs: []netip.Addr{v4Self},
			wantHit:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := FindOverlayRouteConflict(tc.existing, tc.selfAddrs...)
			if ok != tc.wantHit {
				t.Fatalf("FindOverlayRouteConflict ok = %v (hit=%s), want %v", ok, hit, tc.wantHit)
			}
		})
	}
}

// TestFindOverlayRouteConflictNoSelf ensures that when the agent has no
// assigned address yet, every overlay-overlapping specific route is a
// conflict — there is nothing to exempt.
func TestFindOverlayRouteConflictNoSelf(t *testing.T) {
	existing := []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32")}
	_, ok := FindOverlayRouteConflict(existing)
	if !ok {
		t.Fatal("expected conflict when selfAddr unset")
	}
}
