package invitation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/v57/hub-service-go/protocol"
)

type acceptanceHub struct {
	mu          sync.Mutex
	claimedBy   string
	consumedBy  string
	enrollments map[string]Enrollment
}

func newAcceptanceHub() *acceptanceHub {
	return &acceptanceHub{enrollments: make(map[string]Enrollment)}
}

func (h *acceptanceHub) Claim(_ context.Context, _ Decoded, transactionID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.consumedBy != "" {
		if h.consumedBy == transactionID {
			return nil
		}
		return errors.New("invite_consumed")
	}
	if h.claimedBy != "" && h.claimedBy != transactionID {
		return errors.New("invite_already_claimed")
	}
	h.claimedBy = transactionID
	return nil
}

func (h *acceptanceHub) Enroll(_ context.Context, _ Decoded, transactionID string, _ JoinIdentity) (Enrollment, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if enrollment, ok := h.enrollments[transactionID]; ok {
		return enrollment, nil
	}
	if h.claimedBy != transactionID {
		return Enrollment{}, errors.New("invitation not claimed")
	}
	enrollment := Enrollment{
		MembershipID: "membership-" + transactionID,
		NetworkID:    "network-1",
		Addresses:    []string{"100.96.0.3"},
	}
	h.enrollments[transactionID] = enrollment
	h.claimedBy = ""
	h.consumedBy = transactionID
	return enrollment, nil
}

func (h *acceptanceHub) Header(context.Context, Enrollment) (HubHeader, error) {
	return HubHeader{Name: "Test Hub"}, nil
}

func (h *acceptanceHub) Release(_ context.Context, _ Decoded, transactionID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.claimedBy == transactionID {
		h.claimedBy = ""
	}
	return nil
}

type acceptanceNode struct {
	mu        sync.Mutex
	running   bool
	direct    bool
	failNext  bool
	openCount int
}

func (n *acceptanceNode) Open(_ context.Context, _ Decoded, _ JoinIdentity) (BootstrapPeer, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.openCount++
	if !n.running || n.failNext {
		n.failNext = false
		return nil, errors.New("node unavailable")
	}
	if !n.direct {
		return nil, errors.New("direct_connect_failed")
	}
	return &acceptancePeer{}, nil
}

type acceptancePeer struct {
	closeError error
}

func (p *acceptancePeer) Close(context.Context) error { return p.closeError }

type acceptanceTunnel struct {
	upError   error
	downError error
}

func (t *acceptanceTunnel) Up(context.Context, Decoded, BootstrapPeer, JoinIdentity) error {
	return t.upError
}

func (t *acceptanceTunnel) Down(context.Context) error { return t.downError }

type boundaryNode struct {
	next Rendezvous
	fail *atomic.Bool
}

func (n boundaryNode) Open(ctx context.Context, decoded Decoded, identity JoinIdentity) (BootstrapPeer, error) {
	if n.fail.CompareAndSwap(true, false) {
		return nil, errors.New("interrupted after stage")
	}
	peer, err := n.next.Open(ctx, decoded, identity)
	if err != nil {
		return nil, err
	}
	return &boundaryPeer{next: peer, fail: n.fail}, nil
}

type boundaryPeer struct {
	next BootstrapPeer
	fail *atomic.Bool
}

func (p *boundaryPeer) Close(ctx context.Context) error {
	if p.fail.CompareAndSwap(true, false) {
		return errors.New("interrupted after persistent commit")
	}
	return p.next.Close(ctx)
}

type boundaryTunnel struct {
	next Tunnel
	up   *atomic.Bool
	down *atomic.Bool
}

func (t boundaryTunnel) Up(ctx context.Context, decoded Decoded, peer BootstrapPeer, identity JoinIdentity) error {
	if t.up.CompareAndSwap(true, false) {
		return errors.New("interrupted after rendezvous")
	}
	return t.next.Up(ctx, decoded, peer, identity)
}

func (t boundaryTunnel) Down(ctx context.Context) error {
	if t.down.CompareAndSwap(true, false) {
		return errors.New("interrupted after local commit")
	}
	return t.next.Down(ctx)
}

type boundaryHub struct {
	next   Hub
	claim  *atomic.Bool
	enroll *atomic.Bool
	header *atomic.Bool
}

func (h boundaryHub) Claim(ctx context.Context, decoded Decoded, transactionID string) error {
	if h.claim.CompareAndSwap(true, false) {
		return errors.New("interrupted after tunnel")
	}
	return h.next.Claim(ctx, decoded, transactionID)
}

func (h boundaryHub) Enroll(ctx context.Context, decoded Decoded, transactionID string, identity JoinIdentity) (Enrollment, error) {
	if h.enroll.CompareAndSwap(true, false) {
		return Enrollment{}, errors.New("interrupted after claim")
	}
	return h.next.Enroll(ctx, decoded, transactionID, identity)
}

func (h boundaryHub) Header(ctx context.Context, enrollment Enrollment) (HubHeader, error) {
	if h.header.CompareAndSwap(true, false) {
		return HubHeader{}, errors.New("interrupted after enrollment record")
	}
	return h.next.Header(ctx, enrollment)
}

func (h boundaryHub) Release(ctx context.Context, decoded Decoded, transactionID string) error {
	return h.next.Release(ctx, decoded, transactionID)
}

type boundaryStore struct {
	next   Store
	stage  *atomic.Bool
	record *atomic.Bool
	commit *atomic.Bool
}

func (s boundaryStore) Stage(ctx context.Context, transactionID string, identity JoinIdentity) (JoinIdentity, error) {
	if s.stage.CompareAndSwap(true, false) {
		return JoinIdentity{}, errors.New("interrupted before stage")
	}
	return s.next.Stage(ctx, transactionID, identity)
}

func (s boundaryStore) RecordEnrollment(ctx context.Context, transactionID string, enrollment Enrollment) error {
	if s.record.CompareAndSwap(true, false) {
		return errors.New("interrupted before enrollment record")
	}
	return s.next.RecordEnrollment(ctx, transactionID, enrollment)
}

func (s boundaryStore) Commit(ctx context.Context, transactionID string, enrollment Enrollment, header HubHeader) (Membership, error) {
	if s.commit.CompareAndSwap(true, false) {
		return Membership{}, errors.New("interrupted before local commit")
	}
	return s.next.Commit(ctx, transactionID, enrollment, header)
}

func (s boundaryStore) Rollback(ctx context.Context, transactionID string) error {
	return s.next.Rollback(ctx, transactionID)
}

func acceptanceJoiner(t *testing.T, hub Hub, node Rendezvous, store Store) Joiner {
	t.Helper()
	return Joiner{
		Node: node, Tunnel: &acceptanceTunnel{}, Hub: hub, Store: store,
		Now: func() time.Time { return testNow }, Timeout: 100 * time.Millisecond,
	}
}

func acceptanceStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func membershipCount(t *testing.T, store *FileStore) int {
	t.Helper()
	index, err := store.loadIndex()
	if err != nil {
		t.Fatal(err)
	}
	return len(index.Memberships)
}

func TestTwoAgentBootstrapAcceptance(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		hub := newAcceptanceHub()
		node := &acceptanceNode{running: true, direct: true}
		store := acceptanceStore(t)
		membership, err := acceptanceJoiner(t, hub, node, store).Join(
			context.Background(), signedInput(t), "joiner-a", JoinIdentity{AgentKey: "joiner-a"},
		)
		if err != nil {
			t.Fatal(err)
		}
		if membership.Alias != "test-hub" || membershipCount(t, store) != 1 {
			t.Fatalf("membership = %+v, count = %d", membership, membershipCount(t, store))
		}
	})

	t.Run("tampering and expiry stop before node", func(t *testing.T) {
		code := signedInput(t)
		raw, err := base64.RawURLEncoding.DecodeString(code)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		value["hubProHost"] = "100.96.0.99"
		tamperedJSON, err := protocol.CanonicalJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		node := &acceptanceNode{running: true, direct: true}
		joiner := acceptanceJoiner(t, newAcceptanceHub(), node, acceptanceStore(t))
		for name, test := range map[string]struct {
			input string
			now   time.Time
		}{
			"tampered": {base64.RawURLEncoding.EncodeToString([]byte(tamperedJSON)), testNow},
			"expired":  {code, testNow.Add(6 * time.Minute)},
		} {
			t.Run(name, func(t *testing.T) {
				joiner.Now = func() time.Time { return test.now }
				if _, err := joiner.Join(context.Background(), test.input, name, JoinIdentity{}); err == nil {
					t.Fatal("invalid invitation accepted")
				}
			})
		}
		if node.openCount != 0 {
			t.Fatalf("invalid invitations reached node %d times", node.openCount)
		}
	})

	t.Run("concurrent single use", func(t *testing.T) {
		hub := newAcceptanceHub()
		node := &acceptanceNode{running: true, direct: true}
		code := signedInput(t)
		results := make(chan error, 2)
		joiners := []Joiner{
			acceptanceJoiner(t, hub, node, acceptanceStore(t)),
			acceptanceJoiner(t, hub, node, acceptanceStore(t)),
		}
		for index, transactionID := range []string{"joiner-a", "joiner-b"} {
			joiner := joiners[index]
			transactionID := transactionID
			go func() {
				_, err := joiner.Join(
					context.Background(), code, transactionID, JoinIdentity{AgentKey: transactionID},
				)
				results <- err
			}()
		}
		successes := 0
		for range 2 {
			if err := <-results; err == nil {
				successes++
			}
		}
		if successes != 1 {
			t.Fatalf("successful redemptions = %d, want 1", successes)
		}
	})

	t.Run("retryable failure", func(t *testing.T) {
		hub := newAcceptanceHub()
		node := &acceptanceNode{running: true, direct: true}
		store := acceptanceStore(t)
		fail := &atomic.Bool{}
		fail.Store(true)
		joiner := acceptanceJoiner(t, boundaryHub{
			next: hub, claim: &atomic.Bool{}, enroll: fail, header: &atomic.Bool{},
		}, node, store)
		if _, err := joiner.Join(context.Background(), signedInput(t), "retry", JoinIdentity{AgentKey: "stable"}); err == nil {
			t.Fatal("expected retryable failure")
		}
		joiner.Hub = hub
		if _, err := joiner.Join(context.Background(), signedInput(t), "retry", JoinIdentity{AgentKey: "stable"}); err != nil {
			t.Fatal(err)
		}
		if membershipCount(t, store) != 1 {
			t.Fatalf("memberships = %d", membershipCount(t, store))
		}
	})

	t.Run("no direct path has bounded no-relay failure", func(t *testing.T) {
		node := &acceptanceNode{running: true, direct: false}
		store := acceptanceStore(t)
		_, err := acceptanceJoiner(t, newAcceptanceHub(), node, store).Join(
			context.Background(), signedInput(t), "no-path", JoinIdentity{},
		)
		if err == nil || !strings.Contains(err.Error(), "direct_connect_failed") {
			t.Fatalf("error = %v", err)
		}
		if membershipCount(t, store) != 0 {
			t.Fatal("no-direct-path failure persisted membership")
		}
	})

	t.Run("node restart then retry", func(t *testing.T) {
		node := &acceptanceNode{running: true, direct: true, failNext: true}
		store := acceptanceStore(t)
		joiner := acceptanceJoiner(t, newAcceptanceHub(), node, store)
		if _, err := joiner.Join(context.Background(), signedInput(t), "restart", JoinIdentity{}); err == nil {
			t.Fatal("expected node restart interruption")
		}
		if _, err := joiner.Join(context.Background(), signedInput(t), "restart", JoinIdentity{}); err != nil {
			t.Fatal(err)
		}
		if node.openCount != 2 || membershipCount(t, store) != 1 {
			t.Fatalf("node opens = %d, memberships = %d", node.openCount, membershipCount(t, store))
		}
	})
}

func TestBootstrapRecoversFromInterruptionAtEveryTransactionBoundary(t *testing.T) {
	boundaries := []string{
		"stage", "node", "tunnel-up", "claim", "enroll", "record", "header",
		"commit", "tunnel-down", "peer-close",
	}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			hub := newAcceptanceHub()
			node := &acceptanceNode{running: true, direct: true}
			store := acceptanceStore(t)
			flags := make(map[string]*atomic.Bool, len(boundaries))
			for _, name := range boundaries {
				flags[name] = &atomic.Bool{}
			}
			flags[boundary].Store(true)
			joiner := Joiner{
				Node: boundaryNode{next: node, fail: flags["node"]},
				Tunnel: boundaryTunnel{
					next: &acceptanceTunnel{}, up: flags["tunnel-up"], down: flags["tunnel-down"],
				},
				Hub: boundaryHub{
					next: hub, claim: flags["claim"], enroll: flags["enroll"],
					header: flags["header"],
				},
				Store: boundaryStore{
					next: store, stage: flags["stage"], record: flags["record"], commit: flags["commit"],
				},
				Now: func() time.Time { return testNow }, Timeout: 100 * time.Millisecond,
			}
			if boundary == "peer-close" {
				joiner.Node = peerFailNode{next: joiner.Node, fail: flags["peer-close"]}
			}
			if _, err := joiner.Join(context.Background(), signedInput(t), "boundary", JoinIdentity{AgentKey: "stable"}); err == nil {
				t.Fatalf("boundary %s did not interrupt", boundary)
			}
			if _, err := joiner.Join(context.Background(), signedInput(t), "boundary", JoinIdentity{AgentKey: "replacement"}); err != nil {
				t.Fatalf("retry after %s: %v", boundary, err)
			}
			if membershipCount(t, store) != 1 {
				t.Fatalf("boundary %s produced %d memberships", boundary, membershipCount(t, store))
			}
			hub.mu.Lock()
			enrollmentCount := len(hub.enrollments)
			hub.mu.Unlock()
			if enrollmentCount != 1 {
				t.Fatalf("boundary %s produced %d remote enrollments", boundary, enrollmentCount)
			}
		})
	}
}

type peerFailNode struct {
	next Rendezvous
	fail *atomic.Bool
}

func (n peerFailNode) Open(ctx context.Context, decoded Decoded, identity JoinIdentity) (BootstrapPeer, error) {
	peer, err := n.next.Open(ctx, decoded, identity)
	if err != nil {
		return nil, err
	}
	return &boundaryPeer{next: peer, fail: n.fail}, nil
}
