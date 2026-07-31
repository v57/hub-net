package supervisor

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeSession struct {
	started  chan struct{}
	stopped  chan struct{}
	fail     chan error
	stopOnce sync.Once
}

func newFakeSession() *fakeSession {
	return &fakeSession{
		started: make(chan struct{}),
		stopped: make(chan struct{}),
		fail:    make(chan error, 1),
	}
}

func (f *fakeSession) Run(ctx context.Context) error {
	close(f.started)
	select {
	case <-ctx.Done():
		f.stopOnce.Do(func() { close(f.stopped) })
		return ctx.Err()
	case err := <-f.fail:
		f.stopOnce.Do(func() { close(f.stopped) })
		return err
	}
}

func (f *fakeSession) Shutdown() {}

func TestFreshSupervisorStartsDisconnected(t *testing.T) {
	var factoryCalls int
	supervisor, err := New(func(Membership) (Session, error) {
		factoryCalls++
		return newFakeSession(), nil
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitRunning(t, supervisor)
	if factoryCalls != 0 {
		t.Fatalf("factory calls = %d, want 0", factoryCalls)
	}
	if got := supervisor.Snapshots(); len(got) != 0 {
		t.Fatalf("snapshots = %v, want empty", got)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context canceled", err)
	}
}

func TestSessionsAreIndependentAndFailureIsolated(t *testing.T) {
	created := make(map[string]*fakeSession)
	var mu sync.Mutex
	supervisor, err := New(func(membership Membership) (Session, error) {
		session := newFakeSession()
		mu.Lock()
		created[membership.ID] = session
		mu.Unlock()
		return session, nil
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitRunning(t, supervisor)

	first := membership(t, "one", "one", "hubnet1")
	second := membership(t, "two", "two", "hubnet2")
	// Same node URL proves node pools are scoped by membership, not URL.
	first.NodeURL = "wss://node.example"
	second.NodeURL = first.NodeURL
	if err := supervisor.Add(first); err != nil {
		t.Fatalf("Add first: %v", err)
	}
	if err := supervisor.Add(second); err != nil {
		t.Fatalf("Add second: %v", err)
	}
	<-created["one"].started
	<-created["two"].started
	if created["one"] == created["two"] {
		t.Fatal("memberships share session instance")
	}

	created["one"].fail <- errors.New("hub unavailable")
	<-created["one"].stopped
	waitStatus(t, supervisor, "one", StatusError)
	select {
	case <-created["two"].stopped:
		t.Fatal("second session stopped when first failed")
	default:
	}
	if statusFor(supervisor.Snapshots(), "two") != StatusConnected {
		t.Fatalf("second status = %s, want connected", statusFor(supervisor.Snapshots(), "two"))
	}

	if err := supervisor.Remove("two"); err != nil {
		t.Fatalf("Remove second: %v", err)
	}
	if got := supervisor.Snapshots(); len(got) != 1 || got[0].Membership.ID != "one" {
		t.Fatalf("snapshots after remove = %#v", got)
	}
	cancel()
	<-done
}

func TestMembershipIsolationAndIdempotency(t *testing.T) {
	supervisor, err := New(func(Membership) (Session, error) { return newFakeSession(), nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitRunning(t, supervisor)

	first := membership(t, "one", "shared", "hubnet1")
	if err := supervisor.Add(first); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := supervisor.Add(first); err != nil {
		t.Fatalf("idempotent Add: %v", err)
	}
	conflict := membership(t, "two", "shared", "hubnet2")
	if err := supervisor.Add(conflict); err == nil {
		t.Fatal("duplicate alias accepted")
	}
	changed := first
	changed.InterfaceName = "different"
	if err := supervisor.Add(changed); err == nil {
		t.Fatal("changed membership accepted as idempotent")
	}
	cancel()
	<-done
}

func TestExactAliasLookupAndHeaderRefresh(t *testing.T) {
	supervisor, err := New(func(Membership) (Session, error) { return newFakeSession(), nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitRunning(t, supervisor)
	entry := membership(t, "one", "Home", "hubnet1")
	entry.Header = "Original"
	if err := supervisor.Add(entry); err != nil {
		t.Fatal(err)
	}
	if _, ok := supervisor.LookupAlias("home"); ok {
		t.Fatal("case-folded alias lookup succeeded")
	}
	snapshot, ok := supervisor.LookupAlias("Home")
	if !ok || snapshot.Membership.ID != "one" {
		t.Fatalf("exact lookup = %#v, %v", snapshot, ok)
	}
	if !supervisor.UpdateHeader("one", "Remote Rename") {
		t.Fatal("header update failed")
	}
	snapshot, _ = supervisor.LookupAlias("Home")
	if snapshot.Membership.Alias != "Home" || snapshot.Membership.Header != "Remote Rename" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	cancel()
	<-done
}

func membership(t *testing.T, id, alias, interfaceName string) Membership {
	t.Helper()
	root := filepath.Join(t.TempDir(), id)
	return Membership{
		ID:               id,
		Alias:            alias,
		HubAddress:       "ws://hub.example",
		NodeURL:          "wss://node.example",
		StateDir:         root,
		IdentityPath:     filepath.Join(root, "profile.identity"),
		WireGuardKeyPath: filepath.Join(root, "wireguard.key"),
		InterfaceName:    interfaceName,
	}
}

func waitRunning(t *testing.T, supervisor *Supervisor) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		supervisor.mu.RLock()
		running := supervisor.running
		supervisor.mu.RUnlock()
		if running {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("supervisor did not start")
}

func waitStatus(t *testing.T, supervisor *Supervisor, id string, want Status) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if statusFor(supervisor.Snapshots(), id) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("membership %s did not reach %s", id, want)
}

func statusFor(snapshots []Snapshot, id string) Status {
	for _, snapshot := range snapshots {
		if snapshot.Membership.ID == id {
			return snapshot.Status
		}
	}
	return ""
}
