// Package peerlink runs this device's peer links (hub-net-node's
// PROTOCOL.md, "Peer links"): direct WireGuard paths to other devices of the
// hub, each named by a hub-signed grant. Every grant, the hub's own for this
// device and each one another device brings in link.incoming, is checked
// here against the hub key this device pinned before anything is installed;
// WireGuard keys come only from those grants, never from the node.
package peerlink

import (
	"errors"
	"net/netip"
	"time"

	"github.com/v57/hub-net-node/linkgrant"
	"github.com/v57/hub-net-node/models"
)

var (
	ErrMalformed     = errors.New("peerlink: malformed grant")
	ErrUntrustedHub  = errors.New("peerlink: grant from another hub")
	ErrNotASide      = errors.New("peerlink: this device is not a side of the grant")
	ErrInvalid       = errors.New("peerlink: grant signature or lifetime invalid")
	ErrInvalidRoutes = errors.New("peerlink: grant routes are not the other side's addresses")
)

// Link is a grant this device checked, seen from this device.
type Link struct {
	Grant models.PeerLinkGrant
	Own   models.PeerLinkSide
	Other models.PeerLinkSide
	// Opens is true when this device is `a`, the side that opens the link.
	Opens bool
	// Routes are what this device sends through the other side.
	Routes    []netip.Prefix
	ExpiresAt time.Time
}

// Verify checks everything this device can know on its own: the hub key it
// pinned, that it is a side, the lifetime and signature, and that the routes
// are the other side's own addresses. Only `hub` links (a member and the
// hub's machine) are taken. What the node said counts for nothing here.
func Verify(grant models.PeerLinkGrant, trustedHubKey, ownKey string, now time.Time) (Link, error) {
	if grant.Version != models.WireVersion || grant.GrantID == "" || grant.Purpose != models.PeerLinkPurposeHub ||
		grant.A.Key == grant.B.Key || grant.A.WireGuardKey == grant.B.WireGuardKey ||
		len(grant.A.Addresses) == 0 || len(grant.B.Addresses) == 0 {
		return Link{}, ErrMalformed
	}
	for _, port := range append(append([]models.PeerLinkPort(nil), grant.AToB...), grant.BToA...) {
		if port.Protocol != "tcp" && port.Protocol != "udp" {
			return Link{}, ErrMalformed
		}
	}
	if trustedHubKey == "" || grant.HubKey != trustedHubKey {
		return Link{}, ErrUntrustedHub
	}
	var link Link
	switch ownKey {
	case grant.A.Key:
		link = Link{Grant: grant, Own: grant.A, Other: grant.B, Opens: true}
	case grant.B.Key:
		link = Link{Grant: grant, Own: grant.B, Other: grant.A}
	default:
		return Link{}, ErrNotASide
	}
	if err := (linkgrant.Verifier{Now: func() time.Time { return now }}).Verify(grant); err != nil {
		return Link{}, errors.Join(ErrInvalid, err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil {
		return Link{}, ErrMalformed
	}
	link.ExpiresAt = expiresAt
	routes := grant.BViaA
	if link.Opens {
		routes = grant.AViaB
	}
	// A hub link carries the other device's own addresses and nothing more
	want := make(map[netip.Prefix]bool, len(link.Other.Addresses))
	for _, address := range link.Other.Addresses {
		parsed, err := netip.ParseAddr(address)
		if err != nil {
			return Link{}, ErrInvalidRoutes
		}
		want[netip.PrefixFrom(parsed, parsed.BitLen())] = true
	}
	if len(routes) != len(want) {
		return Link{}, ErrInvalidRoutes
	}
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil || !want[prefix] {
			return Link{}, ErrInvalidRoutes
		}
		delete(want, prefix)
		link.Routes = append(link.Routes, prefix)
	}
	return link, nil
}
