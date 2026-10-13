package profile

import (
	"testing"

	"github.com/v57/hub-net-node/identity"
)

func mustIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id
}

func TestNewRejectsNilIdentity(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatalf("expected error for nil identity")
	}
}

func TestProfileLifecycle(t *testing.T) {
	id := mustIdentity(t)
	p, err := New(id)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pub, _ := id.PublicKeyBase64()
	if p.Key() != pub {
		t.Fatalf("Key mismatch")
	}
	if p.State() != StateUnregistered {
		t.Fatalf("initial state = %s, want unregistered", p.State())
	}

	p.BeginRegistration()
	if p.State() != StateRegistering {
		t.Fatalf("state = %s, want registering", p.State())
	}

	wg := make([]byte, 32)
	for i := range wg {
		wg[i] = byte(i)
	}
	p.SetWireGuardPublicKey(wg)
	if got := p.WireGuardPublicKey(); len(got) != 32 {
		t.Fatalf("wg pub key length = %d", len(got))
	}

	p.ConfirmRegistration("100.96.0.1", "hub-net-id-1", 7)
	snap := p.Snapshot()
	if snap.State != StateRegistered {
		t.Fatalf("state = %s, want registered", snap.State)
	}
	if snap.OverlayAddress != "100.96.0.1" {
		t.Fatalf("overlay = %s", snap.OverlayAddress)
	}
	if snap.Generation != 7 {
		t.Fatalf("generation = %d", snap.Generation)
	}

	p.MarkRevoked()
	if p.State() != StateRevoked {
		t.Fatalf("state = %s, want revoked", p.State())
	}
}

func TestSnapshotIsImmutableCopy(t *testing.T) {
	id := mustIdentity(t)
	p, _ := New(id)
	wg := []byte{1, 2, 3}
	for i := 4; i < 32; i++ {
		wg = append(wg, byte(i))
	}
	p.SetWireGuardPublicKey(wg)
	snap := p.Snapshot()
	snap.WireGuardPubKey[0] = 255
	if p.WireGuardPublicKey()[0] == 255 {
		t.Fatalf("snapshot mutated underlying profile")
	}
}
