package invitation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreResumesIdentityAndCommitsAtomically(t *testing.T) {
	root := t.TempDir()
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	identity := JoinIdentity{Key: "agent", WireGuardKey: "wireguard"}
	if _, err := store.Stage(ctx, "transaction-1", identity); err != nil {
		t.Fatal(err)
	}
	resumed, err := store.Stage(ctx, "transaction-1", JoinIdentity{Key: "replacement"})
	if err != nil {
		t.Fatal(err)
	}
	if resumed != identity {
		t.Fatalf("identity changed on resume: %+v", resumed)
	}
	enrollment := Enrollment{MembershipID: "membership-1", NetworkID: "network-1", Addresses: []string{"100.96.0.2"}}
	if err := store.RecordEnrollment(ctx, "transaction-1", enrollment); err != nil {
		t.Fatal(err)
	}
	membership, err := store.Commit(ctx, "transaction-1", enrollment, HubHeader{Name: "Home Hub"})
	if err != nil {
		t.Fatal(err)
	}
	if membership.ID != "membership-1" || membership.Alias != "home-hub" {
		t.Fatalf("membership = %+v", membership)
	}
	raw, err := os.ReadFile(filepath.Join(root, "memberships.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index membershipIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Memberships) != 1 {
		t.Fatalf("memberships = %d", len(index.Memberships))
	}
	info, err := os.Stat(filepath.Join(root, "memberships.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("index mode = %o", info.Mode().Perm())
	}
}

func TestFileStoreRecoversInterruptedLocalCommitExactlyOnce(t *testing.T) {
	root := t.TempDir()
	first, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	identity := JoinIdentity{Key: "stable"}
	if _, err := first.Stage(ctx, "transaction-1", identity); err != nil {
		t.Fatal(err)
	}
	enrollment := Enrollment{MembershipID: "membership-1"}
	if err := first.RecordEnrollment(ctx, "transaction-1", enrollment); err != nil {
		t.Fatal(err)
	}

	// Simulate process interruption by constructing a new store over same root.
	restarted, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := restarted.Stage(ctx, "transaction-1", JoinIdentity{Key: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	if resumed != identity {
		t.Fatalf("resume identity = %+v", resumed)
	}
	firstCommit, err := restarted.Commit(ctx, "transaction-1", enrollment, HubHeader{Name: "Hub"})
	if err != nil {
		t.Fatal(err)
	}

	// Recreate same transaction after remote idempotent enrollment response.
	if _, err := restarted.Stage(ctx, "transaction-1", identity); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RecordEnrollment(ctx, "transaction-1", enrollment); err != nil {
		t.Fatal(err)
	}
	secondCommit, err := restarted.Commit(ctx, "transaction-1", enrollment, HubHeader{Name: "Changed"})
	if err != nil {
		t.Fatal(err)
	}
	if secondCommit != firstCommit {
		t.Fatalf("idempotent commit changed: %+v != %+v", secondCommit, firstCommit)
	}
	index, err := restarted.loadIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Memberships) != 1 {
		t.Fatalf("duplicate memberships: %+v", index.Memberships)
	}
}

func TestNextAliasCollisionSequence(t *testing.T) {
	records := []storedMembership{
		{Membership: Membership{Alias: "hub"}},
		{Membership: Membership{Alias: "hub-2"}},
	}
	if alias := nextAlias("Hub", records); alias != "hub-3" {
		t.Fatalf("alias = %q", alias)
	}
	if alias := nextAlias("Hub-1", records); alias != "hub-1" {
		t.Fatalf("alias = %q", alias)
	}
	if alias := nextAlias("   ", records); alias != "hub-3" {
		t.Fatalf("empty alias = %q", alias)
	}
}
