package invitation

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"
)

type fakePeer struct{ calls *[]string }

func (f fakePeer) Close(context.Context) error { *f.calls = append(*f.calls, "node.close"); return nil }

type fakeNode struct {
	calls *[]string
	err   error
	block bool
}

func (f fakeNode) Open(ctx context.Context, _ Decoded, _ JoinIdentity) (BootstrapPeer, error) {
	*f.calls = append(*f.calls, "node.open")
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return fakePeer{f.calls}, f.err
}

type fakeTunnel struct {
	calls *[]string
	upErr error
}

func (f fakeTunnel) Up(context.Context, Decoded, BootstrapPeer, JoinIdentity) error {
	*f.calls = append(*f.calls, "tunnel.up")
	return f.upErr
}
func (f fakeTunnel) Down(context.Context) error {
	*f.calls = append(*f.calls, "tunnel.down")
	return nil
}

type fakeHub struct {
	calls  *[]string
	failAt string
}

func (f fakeHub) Claim(context.Context, Decoded, string) error {
	*f.calls = append(*f.calls, "hub.claim")
	if f.failAt == "claim" {
		return errors.New("claim failed")
	}
	return nil
}
func (f fakeHub) Enroll(context.Context, Decoded, string, JoinIdentity) (Enrollment, error) {
	*f.calls = append(*f.calls, "hub.enroll")
	if f.failAt == "enroll" {
		return Enrollment{}, errors.New("enroll failed")
	}
	return Enrollment{MembershipID: "membership-1"}, nil
}
func (f fakeHub) Header(context.Context, Enrollment) (HubHeader, error) {
	*f.calls = append(*f.calls, "hub.header")
	if f.failAt == "header" {
		return HubHeader{}, errors.New("header failed")
	}
	return HubHeader{Name: "Home"}, nil
}
func (f fakeHub) Release(context.Context, Decoded, string) error {
	*f.calls = append(*f.calls, "hub.release")
	return nil
}

type fakeStore struct {
	calls      *[]string
	failCommit bool
	failRecord bool
	staged     JoinIdentity
}

func (f *fakeStore) Stage(_ context.Context, _ string, identity JoinIdentity) (JoinIdentity, error) {
	*f.calls = append(*f.calls, "store.stage")
	if f.staged == (JoinIdentity{}) {
		f.staged = identity
	}
	return f.staged, nil
}
func (f *fakeStore) RecordEnrollment(context.Context, string, Enrollment) error {
	*f.calls = append(*f.calls, "store.record-enrollment")
	if f.failRecord {
		return errors.New("record enrollment failed")
	}
	return nil
}
func (f *fakeStore) Commit(context.Context, string, Enrollment, HubHeader) (Membership, error) {
	*f.calls = append(*f.calls, "store.commit")
	if f.failCommit {
		return Membership{}, errors.New("commit failed")
	}
	return Membership{ID: "membership-1", Alias: "home"}, nil
}
func (f *fakeStore) Rollback(context.Context, string) error {
	*f.calls = append(*f.calls, "store.rollback")
	return nil
}

func newJoiner(calls *[]string, failAt string) Joiner {
	return Joiner{
		Node:   fakeNode{calls: calls},
		Tunnel: fakeTunnel{calls: calls},
		Hub:    fakeHub{calls: calls, failAt: failAt},
		Store:  &fakeStore{calls: calls, failCommit: failAt == "commit", failRecord: failAt == "record"},
		Now:    func() time.Time { return testNow },
	}
}

func TestJoinSuccessUsesOrderedBoundedBootstrap(t *testing.T) {
	var calls []string
	joiner := newJoiner(&calls, "")
	membership, err := joiner.Join(context.Background(), signedInput(t), "transaction-1", JoinIdentity{AgentKey: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if membership.Alias != "home" {
		t.Fatalf("unexpected membership: %#v", membership)
	}
	want := []string{"store.stage", "node.open", "tunnel.up", "hub.claim", "hub.enroll", "store.record-enrollment", "hub.header", "store.commit", "tunnel.down", "node.close"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestJoinFailureReleasesAndRollsBackInOrder(t *testing.T) {
	var calls []string
	joiner := newJoiner(&calls, "header")
	_, err := joiner.Join(context.Background(), signedInput(t), "transaction-1", JoinIdentity{})
	if err == nil {
		t.Fatal("expected failure")
	}
	want := []string{"store.stage", "node.open", "tunnel.up", "hub.claim", "hub.enroll", "store.record-enrollment", "hub.header", "tunnel.down", "node.close"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestJoinFailureBeforeEnrollmentReleasesAndRollsBack(t *testing.T) {
	var calls []string
	joiner := newJoiner(&calls, "enroll")
	_, err := joiner.Join(context.Background(), signedInput(t), "transaction-1", JoinIdentity{})
	if err == nil {
		t.Fatal("expected failure")
	}
	want := []string{"store.stage", "node.open", "tunnel.up", "hub.claim", "hub.enroll", "hub.release", "tunnel.down", "node.close", "store.rollback"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestJoinCommitFailurePreservesStagedTransaction(t *testing.T) {
	var calls []string
	store := &fakeStore{calls: &calls, failCommit: true}
	joiner := newJoiner(&calls, "")
	joiner.Store = store
	_, err := joiner.Join(context.Background(), signedInput(t), "transaction-1", JoinIdentity{AgentKey: "stable"})
	if err == nil {
		t.Fatal("expected commit failure")
	}
	if store.staged.AgentKey != "stable" {
		t.Fatalf("staged identity lost: %+v", store.staged)
	}
	for _, forbidden := range []string{"hub.release", "store.rollback"} {
		if slices.Contains(calls, forbidden) {
			t.Fatalf("%s called after remote enrollment: %v", forbidden, calls)
		}
	}
}

func TestJoinRejectsInvalidCodeBeforeSideEffects(t *testing.T) {
	var calls []string
	joiner := newJoiner(&calls, "")
	if _, err := joiner.Join(context.Background(), "not-valid!", "transaction-1", JoinIdentity{}); err == nil {
		t.Fatal("expected validation error")
	}
	if len(calls) != 0 {
		t.Fatalf("unexpected side effects: %v", calls)
	}
}

func TestJoinBoundsDirectPathAndRollsBack(t *testing.T) {
	var calls []string
	joiner := newJoiner(&calls, "")
	joiner.Node = fakeNode{calls: &calls, block: true}
	joiner.Timeout = time.Millisecond
	_, err := joiner.Join(context.Background(), signedInput(t), "transaction-1", JoinIdentity{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	want := []string{"store.stage", "node.open", "store.rollback"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}
