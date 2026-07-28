package keychain

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/v57/hub-service-go/identity"
)

func TestIdentityStorageLoadOrGenerateCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id")
	store := NewIdentityStorage(path)
	if store.Exists() {
		t.Fatalf("identity should not exist yet")
	}
	first, err := store.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate first: %v", err)
	}
	if !store.Exists() {
		t.Fatalf("identity file not created")
	}
	if mode := mustMode(t, path); mode != 0o600 {
		t.Fatalf("identity mode = %v, want 0600", mode)
	}
	second, err := store.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate second: %v", err)
	}
	firstPub, _ := first.PublicKeyBase64()
	secondPub, _ := second.PublicKeyBase64()
	if firstPub != secondPub {
		t.Fatalf("identity not persistent: %s != %s", firstPub, secondPub)
	}
}

func TestIdentityStorageRoundTripsExplicitIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id")
	store := NewIdentityStorage(path)
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	blob, err := ForceEncodeIdentityForTest(id)
	if err != nil {
		t.Fatalf("ForceEncodeIdentityForTest: %v", err)
	}
	if err := store.Write(blob); err != nil {
		t.Fatalf("Write: %v", err)
	}
	loaded, err := store.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	want, _ := id.PublicKeyBase64()
	got, _ := loaded.PublicKeyBase64()
	if want != got {
		t.Fatalf("identity pubkey changed across persistence: %s != %s", want, got)
	}
}

func TestWireGuardStorageLoadOrGenerateCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg")
	store := NewWireGuardStorage(path)
	first, err := store.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate first: %v", err)
	}
	if len(first) != PrivateKeyLength {
		t.Fatalf("key length = %d, want %d", len(first), PrivateKeyLength)
	}
	if mode := mustMode(t, path); mode != 0o600 {
		t.Fatalf("wireguard mode = %v, want 0600", mode)
	}
	second, err := store.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate second: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("wireguard key not persistent")
	}
}

func TestWireGuardStorageRotateChangesKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg")
	store := NewWireGuardStorage(path)
	original, err := store.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	rotated, err := store.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if bytes.Equal(original, rotated) {
		t.Fatalf("Rotate returned same key")
	}
	if mode := mustMode(t, path); mode != 0o600 {
		t.Fatalf("wireguard mode after rotate = %v, want 0600", mode)
	}
}

func TestStorageRefusesEmptyWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg")
	store := New(path)
	if err := store.Write(nil); err == nil {
		t.Fatalf("Write(nil) should fail")
	}
}

func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}
