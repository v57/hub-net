package netapi

import (
	"os"
	"path/filepath"
	"testing"

	protocol "github.com/v57/hub-net-node/models"
)

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

func TestUsersListLeavesOutEitherSelfKey(t *testing.T) {
	registry := NewRegistry()
	registry.Replace([]protocol.AgentProfile{
		{Key: "service-self", OverlayAddresses: []string{"100.96.0.2"}},
		{Key: "device:self", OverlayAddresses: []string{"100.96.0.3"}},
		{Key: "device:peer", OverlayAddresses: []string{"100.96.0.4"}},
	})
	options := Options{Registry: registry, AgentID: func() string { return "service-self" },
		Self: func(id string) bool { return id == "service-self" || id == "device:self" }}
	list := users(options)
	if len(list) != 1 || list[0].ID != "device:peer" || list[0].IP != "100.96.0.4" || list[0].TCP == nil || len(list[0].TCP) != 0 {
		t.Fatalf("users = %+v", list)
	}
	options.Self = nil
	if list := users(options); len(list) != 2 {
		t.Fatalf("default self filter: %+v", list)
	}
}
