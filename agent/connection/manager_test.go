package connection

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/v57/hub-net/grant"
	"github.com/v57/hub-net/wireguard"
	"github.com/v57/hub-service-go/protocol"
)

type checker struct {
	fail map[string]bool
	seen []string
}

func (c *checker) Check(_ context.Context, candidate protocol.Candidate) error {
	c.seen = append(c.seen, candidate.CandidateID)
	if c.fail[candidate.CandidateID] {
		return errors.New("unreachable")
	}
	return nil
}

type handshakes struct {
	failures int
	calls    int
}

func (h *handshakes) Wait(context.Context, []byte) error {
	h.calls++
	if h.calls <= h.failures {
		return errors.New("no handshake")
	}
	return nil
}

func TestConnectTriesPriorityOrderAndRequiresHandshake(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	manager, adapter, connectionGrant, targetAgent := testManager(t, now, 0)
	low := candidate("low", targetAgent, 10, now)
	high := candidate("high", targetAgent, 100, now)
	manager.candidates.(*checker).fail["high"] = true

	if err := manager.Connect(context.Background(), connectionGrant, []protocol.Candidate{low, high}); err != nil {
		t.Fatal(err)
	}
	if got := manager.candidates.(*checker).seen; len(got) != 2 || got[0] != "high" || got[1] != "low" {
		t.Fatalf("candidate order = %v", got)
	}
	state, _ := adapter.State()
	if len(state.Peers) != 1 || state.Peers[0].Endpoint != "198.51.100.10:51820" {
		t.Fatalf("configured peers = %+v", state.Peers)
	}
	if got := manager.Diagnostics(); got[len(got)-1].Code != "direct_connected" {
		t.Fatalf("diagnostic = %+v", got)
	}
}

func TestConnectRejectsWrongAgentAndHasNoRelayFallback(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	manager, _, connectionGrant, _ := testManager(t, now, 0)
	err := manager.Connect(context.Background(), connectionGrant, []protocol.Candidate{
		candidate("substituted", "wrong-agent", 100, now),
	})
	if !errors.Is(err, ErrDirectFailed) {
		t.Fatalf("error = %v", err)
	}
	if manager.handshake.(*handshakes).calls != 0 || len(manager.Peers()) != 0 {
		t.Fatal("unauthorized candidate reached data path")
	}
	got := manager.Diagnostics()
	if got[len(got)-1].Attempts != 0 || got[len(got)-1].Message != "no valid direct candidate" {
		t.Fatalf("diagnostic = %+v", got)
	}
}

func TestFailedHandshakeRemovesPeer(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	manager, adapter, connectionGrant, targetAgent := testManager(t, now, 1)
	err := manager.Connect(context.Background(), connectionGrant, []protocol.Candidate{
		candidate("direct", targetAgent, 100, now),
	})
	if !errors.Is(err, ErrDirectFailed) {
		t.Fatalf("error = %v", err)
	}
	state, _ := adapter.State()
	if len(state.Peers) != 0 {
		t.Fatalf("failed handshake left peer = %+v", state.Peers)
	}
}

func TestPruneIdleAndTouch(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	manager, adapter, connectionGrant, targetAgent := testManager(t, now, 0)
	if err := manager.Connect(context.Background(), connectionGrant, []protocol.Candidate{
		candidate("direct", targetAgent, 100, now),
	}); err != nil {
		t.Fatal(err)
	}
	clock := now.Add(4 * time.Minute)
	manager.now = func() time.Time { return clock }
	key := manager.Peers()[0].PublicKey
	if !manager.Touch(key) {
		t.Fatal("touch missed peer")
	}
	clock = clock.Add(4 * time.Minute)
	if err := manager.PruneIdle(); err != nil {
		t.Fatal(err)
	}
	if len(manager.Peers()) != 1 {
		t.Fatal("peer pruned before idle timeout")
	}
	clock = clock.Add(2 * time.Minute)
	if err := manager.PruneIdle(); err != nil {
		t.Fatal(err)
	}
	state, _ := adapter.State()
	if len(manager.Peers()) != 0 || len(state.Peers) != 0 {
		t.Fatal("idle peer not removed")
	}
}

func testManager(t *testing.T, now time.Time, handshakeFailures int) (*Manager, *wireguard.FakeAdapter, protocol.ConnectionGrant, string) {
	t.Helper()
	hubPublic, hubPrivate, _ := ed25519.GenerateKey(rand.Reader)
	hubDER, _ := x509.MarshalPKIXPublicKey(hubPublic)
	hubKey := base64.StdEncoding.EncodeToString(hubDER)
	localWG := make([]byte, 32)
	targetWG := make([]byte, 32)
	_, _ = rand.Read(localWG)
	_, _ = rand.Read(targetWG)
	localWG64 := base64.StdEncoding.EncodeToString(localWG)
	targetWG64 := base64.StdEncoding.EncodeToString(targetWG)
	connectionGrant := protocol.ConnectionGrant{
		Version: 1, GrantID: "grant-1", HubKey: hubKey, HubNetworkID: "network-1",
		CallerProfileKey: "caller-profile", CallerWireGuardKey: localWG64,
		CallerAddress: "100.96.0.2", TargetAgentKey: "target-agent",
		TargetWireGuardKey: targetWG64, ResourceID: "resource-1", ProviderID: "provider-1",
		Protocol: "tcp", DestinationAddress: "100.96.0.3", DestinationPort: 25565,
		Generation: 7, IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	signature, err := protocol.SignEnvelope(protocol.PurposeConnectionGrant, connectionGrant, hubPrivate)
	if err != nil {
		t.Fatal(err)
	}
	connectionGrant.Signature = signature
	verifier, err := grant.NewVerifier(grant.LocalBinding{
		HubKey: hubKey, HubNetworkID: "network-1", CallerProfileKey: "caller-profile",
		CallerWireGuardKey: localWG64,
	}, func(string) (uint64, bool) { return 7, true })
	if err != nil {
		t.Fatal(err)
	}
	verifierNow := now
	// Tests are deterministic while protocol lifetime remains realistic.
	_ = verifierNow
	adapter := wireguard.NewFakeAdapter()
	if err := adapter.Up(wireguard.InterfaceConfig{}); err != nil {
		t.Fatal(err)
	}
	manager, err := New(Options{
		Adapter: adapter, Verifier: verifier, CandidateChecker: &checker{fail: map[string]bool{}},
		HandshakeChecker: &handshakes{failures: handshakeFailures},
		HandshakeTimeout: time.Second, IdleTimeout: 5 * time.Minute, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Grant verifier uses wall time, so rebuild timestamps around wall time.
	wall := time.Now()
	connectionGrant.IssuedAt = wall.Add(-time.Second).Format(time.RFC3339Nano)
	connectionGrant.ExpiresAt = wall.Add(time.Minute).Format(time.RFC3339Nano)
	signature, _ = protocol.SignEnvelope(protocol.PurposeConnectionGrant, connectionGrant, hubPrivate)
	connectionGrant.Signature = signature
	return manager, adapter, connectionGrant, "target-agent"
}

func candidate(id, agent string, priority uint32, now time.Time) protocol.Candidate {
	return protocol.Candidate{
		Version: 1, CandidateID: id, SessionID: "session-1", AgentKey: agent,
		Kind: "host", Transport: "udp", Address: "198.51.100.10", Port: 51820,
		Priority: priority, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
}
