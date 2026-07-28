// route.go provides the cross-platform route primitives for the Hub Network
// overlay (HN-304): the overlay routes every WireGuard adapter MUST install
// when bringing up the profile interface, and the overlap check every adapter
// MUST run before installing them.
//
// Like netlink.go this file carries no Linux build constraint: the route set
// and the overlap decision are pure arithmetic over netip.Prefix, so the
// encode/decode/overlap tests in route_test.go run on every platform. Only the
// Linux adapter opens a real rtnetlink socket (adapter_linux.go); other
// platforms wire their own syscall plumbing in later tasks.

package wireguard

import (
	"errors"
	"net/netip"
)

// OverlayRoutes returns the routes an adapter installs so traffic for the Hub
// Network overlay prefixes is directed into the profile interface. They are
// scoped to the frozen overlay prefixes (protocol-foundations.md); neither
// equals a default route, so installing them does NOT change the default
// internet route (overlay-addressing spec "Overlay routes scoped").
func OverlayRoutes() []netip.Prefix {
	return []netip.Prefix{IPv4OverlayPrefix, IPv6OverlayPrefix}
}

// FindOverlayRouteConflict reports the first existing route that would steal
// traffic from a Hub Network overlay prefix (HN-304). existing MUST be the
// route table visible to the agent (typically RTM_GETROUTE on Linux).
//
// A route steals overlay traffic only when it is at least as specific as the
// overlay prefix AND shares addresses with it. A broader route (a default
// route, or 100.64.0.0/10) does NOT conflict: the overlay /11 is more
// specific and wins, exactly as the overlay-addressing spec "Overlay routes
// scoped" requires ("request follow existing non-Hub default route" for
// non-overlay traffic). An equal-prefix or more-specific route inside the
// overlay is a conflict — the agent would not actually own the overlay.
//
// Self-routes for the agent's assigned overlay addresses are expected: the
// adapter installs them as part of bringing the interface up, and a stale
// self-route from a previous run is harmless. selfAddrs filters those out.
func FindOverlayRouteConflict(existing []netip.Prefix, selfAddrs ...netip.Addr) (netip.Prefix, bool) {
	for _, route := range existing {
		if isSelfRoute(route, selfAddrs...) {
			continue
		}
		if overlapsOverlaySpecifically(route) {
			return route, true
		}
	}
	return netip.Prefix{}, false
}

// isSelfRoute reports whether route is one of the agent's own overlay
// self-routes (a /32 or /128 host route whose address equals an assigned
// overlay address). Such routes are expected after address assignment and do
// not conflict.
func isSelfRoute(route netip.Prefix, selfAddrs ...netip.Addr) bool {
	if route.Bits() != 32 && route.Bits() != 128 {
		return false
	}
	for _, self := range selfAddrs {
		if !self.IsValid() {
			continue
		}
		if route.Addr() == self {
			return true
		}
	}
	return false
}

// overlapsOverlaySpecifically reports whether route is at least as specific as
// an overlay prefix and shares addresses with it. Broader routes (default,
// carrier-grade NAT aggregates that contain the overlay) do NOT match: the
// more-specific overlay route the adapter installs supersedes them.
func overlapsOverlaySpecifically(route netip.Prefix) bool {
	for _, overlay := range OverlayRoutes() {
		if route.Bits() >= overlay.Bits() && route.Overlaps(overlay) {
			return true
		}
	}
	return false
}

// ErrRouteUnreachable is returned by parseRouteMessage helpers when a netlink
// route dump is too short to interpret. Kept here (not netlink.go) because it
// is specific to the route-install path added in HN-304.
var ErrRouteUnreachable = errors.New("wireguard: route message truncated")
