package peerlink

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
)

// fakeWire is WireGuard as one device's link manager sees it, without a node:
// the session it already has with the other side (endpoint, handshake),
// whether it follows the other side's packets (the kernel module and
// WireGuardNT roam) or keeps the endpoint it's given, and where a handshake
// completes once WireGuard is pointed there (answers).
type fakeWire struct {
	mu        sync.Mutex
	endpoint  string
	handshake time.Time
	follows   bool
	answers   string
	applied   map[string][]string
	opens     int
	logs      bytes.Buffer
}

func newFakeWire(endpoint string, handshake time.Time, follows bool) *fakeWire {
	return &fakeWire{endpoint: endpoint, handshake: handshake, follows: follows, applied: make(map[string][]string)}
}

func (w *fakeWire) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.logs.Write(p)
}

// manager runs a link manager for ownKey on this wire until the test ends.
func (w *fakeWire) manager(t *testing.T, ownKey, candidate string) *Manager {
	t.Helper()
	own := netip.MustParseAddrPort(candidate)
	manager := New(ownKey, Dependencies{
		Open: func(context.Context, models.PeerLinkGrant) (Opened, error) {
			w.mu.Lock()
			w.opens++
			w.mu.Unlock()
			return Opened{LinkID: "link-1", ProbeToken: "token", PeerKey: "machine"}, nil
		},
		Send:  func(protocol.MessageType, string, []models.LinkEndpoint) error { return nil },
		Probe: func(context.Context, []byte) error { return nil },
		Apply: w.apply,
		LastHandshake: func(string) (time.Time, bool) {
			w.mu.Lock()
			defer w.mu.Unlock()
			return w.handshake, !w.handshake.IsZero()
		},
		LiveEndpoint: func(string) (string, bool) {
			w.mu.Lock()
			defer w.mu.Unlock()
			return w.endpoint, w.endpoint != ""
		},
		Candidates: func() []models.LinkEndpoint {
			return []models.LinkEndpoint{{Address: own.Addr().String(), Port: own.Port()}}
		},
		Logger: slog.New(slog.NewTextHandler(w, nil)),
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go manager.Run(ctx)
	return manager
}

func (w *fakeWire) apply(peers []Peer) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, peer := range peers {
		if peer.Endpoint == "" {
			continue
		}
		if list := w.applied[peer.WireGuardKey]; len(list) == 0 || list[len(list)-1] != peer.Endpoint {
			w.applied[peer.WireGuardKey] = append(list, peer.Endpoint)
		}
		if !w.follows {
			w.endpoint = peer.Endpoint
		}
		if peer.Endpoint == w.answers {
			w.endpoint = peer.Endpoint
			w.handshake = time.Now()
		}
	}
	return nil
}

// reach is a handshake at endpoint just now, as another link to the same
// device would make.
func (w *fakeWire) reach(endpoint string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.endpoint = endpoint
	w.handshake = time.Now()
}

func (w *fakeWire) endpointsApplied(wireGuardKey string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.applied[wireGuardKey]...)
}

func (w *fakeWire) logged(text string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Contains(w.logs.String(), text)
}

func (w *fakeWire) waitLog(t *testing.T, text string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !w.logged(text) {
		if time.Now().After(deadline) {
			w.mu.Lock()
			defer w.mu.Unlock()
			t.Fatalf("no %q in\n%s", text, w.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func readyEnvelope(endpoints []string, observed string, punchAt time.Time) protocol.Envelope {
	envelope := protocol.Envelope{Type: protocol.MessageLinkReady, LinkID: "link-1",
		PunchAt: punchAt.UTC().Format(time.RFC3339Nano)}
	for _, endpoint := range endpoints {
		parsed := netip.MustParseAddrPort(endpoint)
		envelope.Endpoints = append(envelope.Endpoints, models.LinkEndpoint{Address: parsed.Addr().String(), Port: parsed.Port()})
	}
	mapping := netip.MustParseAddrPort(observed)
	envelope.Observed = &protocol.ObservedEndpoint{Address: mapping.Addr().String(), Port: mapping.Port()}
	return envelope
}

// startMember brings the member's hub link to the machine to link.open, so a
// link.ready for link-1 follows.
func startMember(t *testing.T, manager *Manager, h hub) {
	t.Helper()
	manager.Update(h.key, []models.PeerLinkGrant{h.grant(t, nil)})
	manager.PresenceChanged(true)
	eventually(t, "the link to open", func() bool { return manager.attemptCount() == 1 })
}

const reachedBefore = `msg="link up, reached before the link"`

// H-032 (H-031 in the Apple app): a member's tunnel restarts on the hub
// machine's LAN. Its profile already points WireGuard at the machine's LAN
// address, so the handshake is done before the link is ready, and WireGuard
// won't make another for two minutes. The link comes up where that session
// runs, without trying the machine's public mapping (no hairpin on a home
// router), which used to flap the path for a minute and then keep the mapping.
func TestARestartedMemberKeepsTheLANPathItReachedBeforeTheLink(t *testing.T) {
	h := newHub(t)
	wire := newFakeWire("192.168.1.6:51820", time.Now().Add(-2*time.Second), false)
	manager := wire.manager(t, "member", "192.168.1.5:60000")
	startMember(t, manager, h)
	manager.Handle(readyEnvelope([]string{"192.168.1.6:51820"}, "185.117.120.25:12230", time.Now()))
	wire.waitLog(t, reachedBefore, 7*time.Second)
	if !wire.logged("at=192.168.1.6:51820") {
		t.Fatal("the link isn't up at the LAN address")
	}
	if applied := wire.endpointsApplied("wg-machine"); len(applied) != 1 || applied[0] != "192.168.1.6:51820" {
		t.Fatalf("endpoints applied = %v, want only the LAN address (the public mapping is never tried)", applied)
	}
	if wire.logged("found no path") {
		t.Fatal("found no path")
	}
	eventually(t, "the attempt to finish", func() bool { return manager.attemptCount() == 0 })
	// The live link isn't opened again
	manager.Update(h.key, []models.PeerLinkGrant{h.grant(t, nil)})
	time.Sleep(200 * time.Millisecond)
	wire.mu.Lock()
	opens := wire.opens
	wire.mu.Unlock()
	if opens != 1 {
		t.Fatalf("link.open sent %d times, want 1", opens)
	}
}

// The machine's side of H-032: the restarted member's handshake reached the
// machine before its link did, and WireGuard (which follows the packets)
// already sends to the member's LAN address, the candidate the member offers.
func TestTheMachineKeepsTheAddressARestartedMemberCameFrom(t *testing.T) {
	h := newHub(t)
	wire := newFakeWire("192.168.1.5:60000", time.Now().Add(-3*time.Second), true)
	manager := wire.manager(t, "machine", "192.168.1.6:51820")
	manager.Update(h.key, nil)
	manager.PresenceChanged(true)
	grant := h.grant(t, nil)
	manager.Handle(protocol.Envelope{Type: protocol.MessageLinkIncoming, LinkID: "link-1", Grant: &grant, ProbeToken: "token", PeerKey: "member"})
	eventually(t, "the accept", func() bool { return manager.attemptCount() == 1 })
	manager.Handle(readyEnvelope([]string{"192.168.1.5:60000"}, "185.117.120.25:4500", time.Now()))
	wire.waitLog(t, reachedBefore, 7*time.Second)
	if applied := wire.endpointsApplied("wg-member"); len(applied) != 1 || applied[0] != "192.168.1.5:60000" {
		t.Fatalf("endpoints applied = %v, want only the member's LAN address", applied)
	}
}

// A profile that names a port the machine no longer listens on reached
// nothing before the link: the link tries the machine's endpoints and comes
// up at the first that answers.
func TestAMemberWhoseProfileEndpointIsStalePunches(t *testing.T) {
	h := newHub(t)
	// An old session at the stale port still looks live: it isn't an endpoint
	// the machine offers now
	wire := newFakeWire("192.168.1.6:54055", time.Now().Add(-100*time.Second), false)
	wire.answers = "192.168.1.6:51820"
	manager := wire.manager(t, "member", "192.168.1.5:60000")
	startMember(t, manager, h)
	manager.Handle(readyEnvelope([]string{"192.168.1.6:51820"}, "185.117.120.25:12230", time.Now()))
	wire.waitLog(t, `msg="link up" link=link-1 peer=machine at=192.168.1.6:51820`, 7*time.Second)
	if wire.logged(reachedBefore) {
		t.Fatal("the stale profile endpoint counted as reached")
	}
}

// Another link to the same device reached it while this one waited for
// punchAt: that handshake counts, rather than a minute of trials that flip
// the endpoint to the other side's public mapping and back.
func TestAHandshakeWhileWaitingToPunchCounts(t *testing.T) {
	h := newHub(t)
	wire := newFakeWire("", time.Time{}, false)
	manager := wire.manager(t, "member", "192.168.1.5:60000")
	startMember(t, manager, h)
	manager.Handle(readyEnvelope([]string{"192.168.1.6:51820"}, "185.117.120.25:12230", time.Now().Add(2*time.Second)))
	time.Sleep(300 * time.Millisecond)
	wire.reach("192.168.1.6:51820")
	wire.waitLog(t, reachedBefore, 7*time.Second)
	if applied := wire.endpointsApplied("wg-machine"); len(applied) != 1 || applied[0] != "192.168.1.6:51820" {
		t.Fatalf("endpoints applied = %v, want only the LAN address", applied)
	}
}

// A later link.ready for the same link cancels the punch running for it: the
// cancelled punch neither logs "found no path" nor ends the attempt its
// successor owns.
func TestALaterReadyOwnsTheAttempt(t *testing.T) {
	h := newHub(t)
	wire := newFakeWire("", time.Time{}, false)
	wire.answers = "203.0.113.9:51820"
	manager := wire.manager(t, "member", "192.168.1.5:60000")
	startMember(t, manager, h)
	manager.Handle(readyEnvelope([]string{"192.168.1.6:51820"}, "185.117.120.25:12230", time.Now()))
	time.Sleep(300 * time.Millisecond)
	manager.Handle(readyEnvelope([]string{"203.0.113.9:51820"}, "185.117.120.25:12230", time.Now()))
	wire.waitLog(t, `msg="link up" link=link-1 peer=machine at=203.0.113.9:51820`, 7*time.Second)
	if wire.logged("found no path") {
		t.Fatal("the cancelled punch logged found no path")
	}
}
