package peerlink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
)

type hub struct {
	key     string
	private ed25519.PrivateKey
}

func newHub(t *testing.T) hub {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(public)
	return hub{key: base64.StdEncoding.EncodeToString(der), private: private}
}

// grant signs a hub link between member `a` and the hub's machine `b`.
func (h hub) grant(t *testing.T, mutate func(*models.PeerLinkGrant)) models.PeerLinkGrant {
	t.Helper()
	now := time.Now().UTC()
	grant := models.PeerLinkGrant{
		Version: models.WireVersion, GrantID: "grant-1", HubKey: h.key, HubNetworkID: "network",
		Purpose: models.PeerLinkPurposeHub,
		A: models.PeerLinkSide{Key: "member", WireGuardKey: "wg-member", Member: "member",
			Addresses: []string{"100.96.0.3", "fd48:5542:4e45::3"}},
		B: models.PeerLinkSide{Key: "machine", WireGuardKey: "wg-machine", Member: "machine",
			Addresses: []string{"100.96.0.2", "fd48:5542:4e45::2"}},
		AViaB: []string{"100.96.0.2/32", "fd48:5542:4e45::2/128"},
		BViaA: []string{"100.96.0.3/32", "fd48:5542:4e45::3/128"},
		AToB:  []models.PeerLinkPort{{Protocol: "tcp", Port: 1997}}, BToA: []models.PeerLinkPort{},
		IssuedAt:  now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(30 * 24 * time.Hour).Format(time.RFC3339Nano),
	}
	if mutate != nil {
		mutate(&grant)
	}
	var err error
	grant.Signature, err = models.SignEnvelope(models.PurposePeerLink, grant, h.private)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func TestVerifySeesTheGrantFromEachSide(t *testing.T) {
	h := newHub(t)
	grant := h.grant(t, nil)
	member, err := Verify(grant, h.key, "member", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !member.Opens || member.Other.Key != "machine" || len(member.Routes) != 2 ||
		member.Routes[0] != netip.MustParsePrefix("100.96.0.2/32") {
		t.Fatalf("member side = %+v", member)
	}
	machine, err := Verify(grant, h.key, "machine", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if machine.Opens || machine.Other.Key != "member" || machine.Routes[1] != netip.MustParsePrefix("fd48:5542:4e45::3/128") {
		t.Fatalf("machine side = %+v", machine)
	}
}

func TestVerifyRejects(t *testing.T) {
	h := newHub(t)
	other := newHub(t)
	for name, check := range map[string]struct {
		grant   models.PeerLinkGrant
		trusted string
		own     string
		want    error
	}{
		"another hub":      {h.grant(t, nil), other.key, "member", ErrUntrustedHub},
		"signed elsewhere": {other.grant(t, func(g *models.PeerLinkGrant) { g.HubKey = h.key }), h.key, "member", ErrInvalid},
		"not a side":       {h.grant(t, nil), h.key, "stranger", ErrNotASide},
		"gateway purpose":  {h.grant(t, func(g *models.PeerLinkGrant) { g.Purpose = models.PeerLinkPurposeGateway }), h.key, "member", ErrMalformed},
		"wider routes": {h.grant(t, func(g *models.PeerLinkGrant) {
			g.AViaB = []string{"100.96.0.0/11", "fd48:5542:4e45::2/128"}
		}), h.key, "member", ErrInvalidRoutes},
		"expired": {h.grant(t, func(g *models.PeerLinkGrant) {
			g.IssuedAt = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
			g.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
		}), h.key, "member", ErrInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(check.grant, check.trusted, check.own, time.Now()); !errors.Is(err, check.want) {
				t.Fatalf("err = %v, want %v", err, check.want)
			}
		})
	}
}

// fakes records what the manager asks of the node and WireGuard.
type fakes struct {
	mu         sync.Mutex
	sent       []string
	probes     [][]byte
	applied    [][]Peer
	handshakes map[string]time.Time
	opened     chan struct{}
}

func (f *fakes) deps() Dependencies {
	return Dependencies{
		Open: func(context.Context, models.PeerLinkGrant) (Opened, error) {
			defer func() { f.opened <- struct{}{} }()
			return Opened{LinkID: "link-1", ProbeToken: "token-a", PeerKey: "machine"}, nil
		},
		Send: func(messageType protocol.MessageType, linkID string, _ []models.LinkEndpoint) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.sent = append(f.sent, string(messageType)+" "+linkID)
			return nil
		},
		Probe: func(_ context.Context, payload []byte) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.probes = append(f.probes, payload)
			return nil
		},
		Apply: func(peers []Peer) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.applied = append(f.applied, peers)
			return nil
		},
		LastHandshake: func(key string) (time.Time, bool) {
			f.mu.Lock()
			defer f.mu.Unlock()
			at, ok := f.handshakes[key]
			return at, ok
		},
		Candidates: func() []models.LinkEndpoint {
			return []models.LinkEndpoint{{Address: "192.168.1.20", Port: 51820}}
		},
	}
}

func (f *fakes) lastApplied() []Peer {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applied) == 0 {
		return nil
	}
	return f.applied[len(f.applied)-1]
}

func eventually(t *testing.T, what string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestMemberOpensProbesAndPunchesUntilAHandshake(t *testing.T) {
	h := newHub(t)
	f := &fakes{handshakes: map[string]time.Time{}, opened: make(chan struct{}, 4)}
	manager := New("member", f.deps())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Run(ctx)

	manager.Update(h.key, []models.PeerLinkGrant{h.grant(t, nil)})
	manager.PresenceChanged(true)
	select {
	case <-f.opened:
	case <-time.After(5 * time.Second):
		t.Fatal("link.open not sent")
	}
	eventually(t, "a probe", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.probes) > 0
	})
	var probe protocol.LinkUDPProbe
	f.mu.Lock()
	_ = json.Unmarshal(f.probes[0], &probe)
	f.mu.Unlock()
	if probe.LinkID != "link-1" || probe.ProbeToken != "token-a" {
		t.Fatalf("probe = %+v", probe)
	}
	eventually(t, "the offer", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.sent) == 1 && f.sent[0] == "link.offer link-1"
	})
	if peers := f.lastApplied(); len(peers) != 1 || peers[0].WireGuardKey != "wg-machine" || peers[0].Endpoint != "" {
		t.Fatalf("peers before ready = %+v", peers)
	}

	manager.Handle(protocol.Envelope{
		Type: protocol.MessageLinkReady, LinkID: "link-1", PeerKey: "machine",
		Observed: &protocol.ObservedEndpoint{Address: "203.0.113.7", Port: 40000},
		PunchAt:  time.Now().UTC().Format(time.RFC3339Nano),
	})
	eventually(t, "the observed endpoint", func() bool {
		peers := f.lastApplied()
		return len(peers) == 1 && peers[0].Endpoint == "203.0.113.7:40000"
	})
	f.mu.Lock()
	f.handshakes["wg-machine"] = time.Now()
	f.mu.Unlock()
	eventually(t, "the link to be up", func() bool { return manager.attemptCount() == 0 })
	// A live path to the same grant isn't opened again
	manager.Update(h.key, []models.PeerLinkGrant{h.grant(t, nil)})
	select {
	case <-f.opened:
		t.Fatal("opened a live link again")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestMachineAcceptsOnlyVerifiedIncomingLinks(t *testing.T) {
	h := newHub(t)
	f := &fakes{handshakes: map[string]time.Time{}, opened: make(chan struct{}, 4)}
	manager := New("machine", f.deps())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Run(ctx)
	manager.Update(h.key, nil)
	manager.PresenceChanged(true)

	forged := newHub(t).grant(t, nil)
	manager.Handle(protocol.Envelope{Type: protocol.MessageLinkIncoming, LinkID: "bad", Grant: &forged, ProbeToken: "t", PeerKey: "member"})
	grant := h.grant(t, nil)
	manager.Handle(protocol.Envelope{Type: protocol.MessageLinkIncoming, LinkID: "good", Grant: &grant, ProbeToken: "t", PeerKey: "member"})
	eventually(t, "reject and accept", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		var reject, accept bool
		for _, sent := range f.sent {
			reject = reject || sent == "link.reject bad"
			accept = accept || sent == "link.accept good"
		}
		return reject && accept
	})
	peers := f.lastApplied()
	if len(peers) != 1 || peers[0].Key != "member" || peers[0].WireGuardKey != "wg-member" ||
		peers[0].Routes[0] != netip.MustParsePrefix("100.96.0.3/32") {
		t.Fatalf("peers = %+v", peers)
	}
	select {
	case <-f.opened:
		t.Fatal("the machine opened a link")
	default:
	}
}

func TestReachableFirstPutsOtherPrivateNetworksLast(t *testing.T) {
	ordered := ReachableFirst([]models.LinkEndpoint{
		{Address: "10.0.0.5", Port: 1}, {Address: "192.168.1.9", Port: 2}, {Address: "203.0.113.7", Port: 3},
	}, []models.LinkEndpoint{{Address: "192.168.1.20", Port: 51820}})
	if ordered[0].Port != 2 || ordered[1].Port != 3 || ordered[2].Port != 1 {
		t.Fatalf("ordered = %+v", ordered)
	}
}
