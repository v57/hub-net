package grant

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/v57/hub-net/wireguard"
	"github.com/v57/hub-service-go/protocol"
)

func TestConfigureOutboundBindsAuthorizedPeer(t *testing.T) {
	verifier, grant := fixture(t)
	adapter := wireguard.NewFakeAdapter()
	if err := adapter.Up(wireguard.InterfaceConfig{Name: "hubnet0"}); err != nil {
		t.Fatal(err)
	}
	if err := verifier.ConfigureOutbound(adapter, grant, "192.0.2.1:51820"); err != nil {
		t.Fatalf("ConfigureOutbound: %v", err)
	}
	state, _ := adapter.State()
	if len(state.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(state.Peers))
	}
	peer := state.Peers[0]
	if got := base64.StdEncoding.EncodeToString(peer.PublicKey); got != grant.TargetWireGuardKey {
		t.Fatalf("peer key = %s", got)
	}
	want := netip.MustParsePrefix("100.96.0.9/32")
	if len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0] != want {
		t.Fatalf("allowed IPs = %v, want [%s]", peer.AllowedIPs, want)
	}
	if peer.Endpoint != "192.0.2.1:51820" {
		t.Fatalf("endpoint = %q", peer.Endpoint)
	}
}

func TestVerifyRejectsMutationsReplayAndStaleGeneration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*protocol.ConnectionGrant)
		want   error
	}{
		{"signature field", func(g *protocol.ConnectionGrant) { g.DestinationPort++ }, ErrInvalidGrant},
		{"Hub network", func(g *protocol.ConnectionGrant) { g.HubNetworkID = "other" }, ErrBindingMismatch},
		{"caller profile", func(g *protocol.ConnectionGrant) { g.CallerProfileKey = "other" }, ErrBindingMismatch},
		{"caller WireGuard key", func(g *protocol.ConnectionGrant) { g.CallerWireGuardKey = key(7) }, ErrBindingMismatch},
		{"outside overlay", func(g *protocol.ConnectionGrant) { g.DestinationAddress = "8.8.8.8" }, ErrInvalidGrant},
		{"target key", func(g *protocol.ConnectionGrant) { g.TargetWireGuardKey = "bad" }, ErrInvalidGrant},
		{"protocol", func(g *protocol.ConnectionGrant) { g.Protocol = "icmp" }, ErrInvalidGrant},
		{"generation", func(g *protocol.ConnectionGrant) { g.Generation++ }, ErrBindingMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, grant := fixture(t)
			test.mutate(&grant)
			if err := verifier.Verify(grant); !errors.Is(err, test.want) {
				t.Fatalf("Verify error = %v, want %v", err, test.want)
			}
		})
	}

	verifier, grant := fixture(t)
	if err := verifier.Verify(grant); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if err := verifier.Verify(grant); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay error = %v, want ErrReplay", err)
	}
}

func TestVerifyRejectsExpiredAndFutureGrant(t *testing.T) {
	verifier, grant := fixture(t)
	verifier.now = func() time.Time { return time.Unix(2_000, 0).UTC() }
	grant.IssuedAt = time.Unix(1_000, 0).UTC().Format(time.RFC3339Nano)
	grant.ExpiresAt = time.Unix(1_060, 0).UTC().Format(time.RFC3339Nano)
	resign(t, &grant)
	if err := verifier.Verify(grant); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired error = %v", err)
	}
}

var fixturePrivate ed25519.PrivateKey

func fixture(t *testing.T) (*Verifier, protocol.ConnectionGrant) {
	t.Helper()
	_, fixturePrivate, _ = ed25519.GenerateKey(nil)
	hubDER, _ := x509.MarshalPKIXPublicKey(fixturePrivate.Public())
	hubKey := base64.StdEncoding.EncodeToString(hubDER)
	now := time.Now().UTC()
	grant := protocol.ConnectionGrant{
		Version:            protocol.WireVersion,
		GrantID:            "grant-1",
		HubKey:             hubKey,
		HubNetworkID:       "network-1",
		CallerProfileKey:   "profile-1",
		CallerWireGuardKey: key(1),
		CallerAddress:      "100.96.0.8",
		TargetAgentKey:     "agent-2",
		TargetWireGuardKey: key(2),
		ResourceID:         "resource-1",
		ProviderID:         "provider-1",
		Protocol:           "tcp",
		DestinationAddress: "100.96.0.9",
		DestinationPort:    9001,
		Generation:         4,
		IssuedAt:           now.Format(time.RFC3339Nano),
		ExpiresAt:          now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	resign(t, &grant)
	verifier, err := NewVerifier(LocalBinding{
		HubKey:             hubKey,
		HubNetworkID:       "network-1",
		CallerProfileKey:   "profile-1",
		CallerWireGuardKey: key(1),
	}, func(resourceID string) (uint64, bool) {
		return 4, resourceID == "resource-1"
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier, grant
}

func resign(t *testing.T, grant *protocol.ConnectionGrant) {
	t.Helper()
	signature, err := protocol.SignEnvelope(protocol.PurposeConnectionGrant, *grant, fixturePrivate)
	if err != nil {
		t.Fatal(err)
	}
	grant.Signature = signature
}

func key(fill byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = fill
	}
	return base64.StdEncoding.EncodeToString(raw)
}
