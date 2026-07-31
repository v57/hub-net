package membership

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func testRecord(id string) Record {
	return Record{ID: id, Alias: id, Header: "Hub " + id, HubAddress: json.RawMessage(`1997`),
		NetworkID: "network-" + id, NodeURL: "wss://node.example", InterfaceName: "hubnet-" + id}
}

func TestStoreCommitRestartAndCorruptionIsolation(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"one", "two"} {
		if err := store.Stage(testRecord(id)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Commit(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(store.recordPath("two"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	records, diagnostics, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Record.ID != "one" {
		t.Fatalf("records = %+v", records)
	}
	if len(diagnostics) != 1 || diagnostics[0].ID != "two" {
		t.Fatalf("diagnostics = %+v", diagnostics)
	}
}

func TestRecoverPublishesRecordWrittenBeforeIndex(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	record := testRecord("one")
	if err := store.Stage(record); err != nil {
		t.Fatal(err)
	}
	if err := store.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	if diagnostics := store.Recover(); len(diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v", diagnostics)
	}
	records, _, err := store.Load()
	if err != nil || len(records) != 1 || records[0].Record.ID != "one" {
		t.Fatalf("records = %+v, err = %v", records, err)
	}
}

func TestSingletonMigrationPreservesFilesAndDisablesGateway(t *testing.T) {
	legacyRoot := t.TempDir()
	identity := []byte("stable-profile-key")
	wireGuard := []byte("stable-wireguard-key")
	publications := []byte(`[{"name":"port-80-tcp"}]`)
	identityPath := filepath.Join(legacyRoot, "profile.identity")
	wireGuardPath := filepath.Join(legacyRoot, "wireguard.key")
	publicationsPath := filepath.Join(legacyRoot, "publications.json")
	for path, data := range map[string][]byte{identityPath: identity, wireGuardPath: wireGuard, publicationsPath: publications} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := Open(filepath.Join(t.TempDir(), "multi"))
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := store.MigrateSingleton(Legacy{ID: "legacy", Alias: "home", Header: "Home",
		HubAddress: json.RawMessage(`"127.0.0.1:1997"`), NetworkID: "network", NodeURL: "wss://node",
		InterfaceName: "hubnet0", IdentityPath: identityPath, WireGuardKeyPath: wireGuardPath,
		PublicationsPath: publicationsPath})
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Record.GatewayAllowed {
		t.Fatal("gateway enabled during migration")
	}
	for path, want := range map[string][]byte{migrated.IdentityPath: identity, migrated.WireGuardKeyPath: wireGuard,
		migrated.Record.PublicationsPath: publications, identityPath: identity, wireGuardPath: wireGuard} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s = %q, %v", path, got, err)
		}
	}
	again, err := store.MigrateSingleton(Legacy{ID: "legacy"})
	if err != nil || again.Record.ID != "legacy" {
		t.Fatalf("repeat migration = %+v, %v", again, err)
	}
}

func TestFindExactAliasAndUpdateHeaderPreservesAlias(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	record := testRecord("one")
	record.Alias = "Home"
	if err := store.Stage(record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(record.ID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.FindAlias("home"); err != nil || found {
		t.Fatalf("case-folded alias found=%v err=%v", found, err)
	}
	found, ok, err := store.FindAlias("Home")
	if err != nil || !ok || found.Record.ID != "one" {
		t.Fatalf("exact lookup = %#v, %v, %v", found, ok, err)
	}
	updated, err := store.UpdateHeader("one", "Renamed Remote Hub")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Record.Alias != "Home" || updated.Record.Header != "Renamed Remote Hub" {
		t.Fatalf("updated record = %#v", updated.Record)
	}
}

func TestUpdateTranslationPersistsOnce(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Stage(testRecord("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit("one"); err != nil {
		t.Fatal(err)
	}
	updated, err := store.UpdateTranslation("one", "10.32.0.0/11", "fd80:1::/48")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Record.TranslatedIPv4 != "10.32.0.0/11" || updated.Record.TranslatedIPv6 != "fd80:1::/48" {
		t.Fatalf("allocation = %#v", updated.Record)
	}
	if _, err := store.UpdateTranslation("one", "10.32.0.0/11", "fd80:1::/48"); err != nil {
		t.Fatalf("idempotent update: %v", err)
	}
	if _, err := store.UpdateTranslation("one", "10.64.0.0/11", "fd80:2::/48"); err == nil {
		t.Fatal("changed allocation accepted")
	}
}

func TestLoadFinishesInterruptedRemoval(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Stage(testRecord("one")); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Commit("one")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stored.IdentityPath, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Simulate crash after membership became unusable but before private
	// directory cleanup and tombstone removal.
	if err := atomicJSON(store.indexPath(), index{
		Version: Version, Removing: []string{"one"},
	}, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(store.root)
	if err != nil {
		t.Fatal(err)
	}
	records, diagnostics, err := restarted.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 || len(diagnostics) != 0 {
		t.Fatalf("records=%+v diagnostics=%+v", records, diagnostics)
	}
	if _, err := os.Stat(stored.StateDir); !os.IsNotExist(err) {
		t.Fatalf("private state survived recovery: %v", err)
	}
	current, err := restarted.readIndex()
	if err != nil || len(current.Removing) != 0 {
		t.Fatalf("removal tombstone survived: %+v, %v", current, err)
	}
}
