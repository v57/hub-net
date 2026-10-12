package netapi

import (
	"os"
	"path/filepath"
	"testing"
)

func boolp(value bool) *bool { return &value }

func TestPortScopesAndReplacement(t *testing.T) {
	store := NewStore()
	set := []UpdatePortsCommand{{Port: 80, TCP: boolp(true), UDP: boolp(false)}}
	if err := store.Apply(UpdatePorts{Set: &set}, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	update := []UpdatePortsCommand{{Port: 53, TCP: boolp(false), UDP: boolp(true)}}
	if err := store.Apply(UpdatePorts{Users: []string{"user"}, Update: &update}, func(id string) bool { return id == "user" }); err != nil {
		t.Fatal(err)
	}
	if got := store.Global(); len(got.TCP) != 1 || got.TCP[0] != 80 || len(got.UDP) != 0 {
		t.Fatalf("global=%+v", got)
	}
	if got := store.User("user"); len(got.UDP) != 1 || got.UDP[0] != 53 || len(got.TCP) != 0 {
		t.Fatalf("user=%+v", got)
	}
	if got := store.Effective("user"); len(got.TCP) != 1 || len(got.UDP) != 1 {
		t.Fatalf("effective=%+v", got)
	}
	empty := []UpdatePortsCommand{}
	if err := store.Apply(UpdatePorts{Users: []string{"user"}, Set: &empty}, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if got := store.User("user"); len(got.TCP)+len(got.UDP) != 0 {
		t.Fatalf("not cleared=%+v", got)
	}
}

func TestPortValidation(t *testing.T) {
	store := NewStore()
	commands := []UpdatePortsCommand{{Port: 1, TCP: boolp(false), UDP: boolp(false)}}
	if err := store.Apply(UpdatePorts{Update: &commands}, func(string) bool { return true }); err == nil {
		t.Fatal("accepted disabled protocols")
	}
	commands = []UpdatePortsCommand{{Port: 1}}
	if err := store.Apply(UpdatePorts{Users: []string{}, Update: &commands}, func(string) bool { return true }); err == nil {
		t.Fatal("accepted empty users")
	}
}

func TestStorePersistsAtomicallyAndRollsBackOnWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ports.json")
	store := NewStore(path)
	set := []UpdatePortsCommand{{Port: 80, TCP: boolp(true), UDP: boolp(false)}}
	if err := store.Apply(UpdatePorts{Set: &set}, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	reloaded := NewStore(path)
	if got := reloaded.Global(); len(got.TCP) != 1 || got.TCP[0] != 80 {
		t.Fatalf("reloaded global=%+v", got)
	}

	// A path whose parent cannot be created must fail the durable write
	// without mutating in-memory state.
	blockedParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := NewStore(filepath.Join(blockedParent, "ports.json"))
	update := []UpdatePortsCommand{{Port: 443, TCP: boolp(true), UDP: boolp(true)}}
	if err := blocked.Apply(UpdatePorts{Update: &update}, func(string) bool { return true }); err == nil {
		t.Fatal("Apply succeeded despite unwritable path")
	}
	if got := blocked.Global(); len(got.TCP) != 0 || len(got.UDP) != 0 {
		t.Fatalf("Apply mutated memory on persist failure: %+v", got)
	}

	// Revoke persists and removes only the revoked user.
	if err := store.Apply(UpdatePorts{Users: []string{"user-a", "user-b"}, Update: &update}, func(id string) bool {
		return id == "user-a" || id == "user-b"
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke("user-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.users["user-a"]; ok {
		t.Fatal("user-a still present after revoke")
	}
	if _, ok := store.users["user-b"]; !ok {
		t.Fatal("user-b unexpectedly revoked")
	}
	if err := store.Revoke("user-a"); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
}

func TestRegistryPersistsRevocationAndDetectsNewKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revoked.json")
	registry := NewRegistry(path)
	if len(registry.Keys()) != 0 {
		t.Fatal("new registry should have no keys")
	}
	if err := registry.Remove("user-a"); err != nil {
		t.Fatal(err)
	}
	reloaded := NewRegistry(path)
	if reloaded.Exists("user-a") {
		t.Fatal("revoked user reappeared after reload")
	}
	if err := registry.Remove("user-a"); err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}

	// Persistence failure leaves the registry unchanged.
	blockedParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := NewRegistry(filepath.Join(blockedParent, "revoked.json"))
	if err := blocked.Remove("user-b"); err == nil {
		t.Fatal("Remove succeeded despite unwritable path")
	}
	if blocked.Exists("user-b") {
		t.Fatal("Remove mutated memory on persist failure")
	}
}
