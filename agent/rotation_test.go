package hubnet

import (
	"bytes"
	"context"
	"testing"
)

func TestRotateWireGuardKeyChangesPublicKey(t *testing.T) {
	agent, err := New(Options{Config: newConfig(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	before := agent.profile.Snapshot().WireGuardPubKey
	if len(before) != 32 {
		t.Fatalf("before length = %d", len(before))
	}

	if err := agent.RotateWireGuardKey(); err != nil {
		t.Fatalf("RotateWireGuardKey: %v", err)
	}
	after := agent.profile.Snapshot().WireGuardPubKey
	if bytes.Equal(before, after) {
		t.Fatalf("rotation did not change public key")
	}
	if len(after) != 32 {
		t.Fatalf("after length = %d", len(after))
	}
}

func TestRotateWireGuardKeyPersists(t *testing.T) {
	cfg := newConfig(t)
	first, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatalf("New first: %v", err)
	}
	if err := first.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare first: %v", err)
	}
	if err := first.RotateWireGuardKey(); err != nil {
		t.Fatalf("RotateWireGuardKey: %v", err)
	}
	rotated := first.profile.Snapshot().WireGuardPubKey

	second, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatalf("New second: %v", err)
	}
	if err := second.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare second: %v", err)
	}
	loaded := second.profile.Snapshot().WireGuardPubKey
	if !bytes.Equal(rotated, loaded) {
		t.Fatalf("rotated key not persisted across instances")
	}
}

func TestRotateKeepsProfileIdentity(t *testing.T) {
	cfg := newConfig(t)
	agent, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	identityBefore := agent.profile.Snapshot().ProfileKey
	if err := agent.RotateWireGuardKey(); err != nil {
		t.Fatalf("RotateWireGuardKey: %v", err)
	}
	identityAfter := agent.profile.Snapshot().ProfileKey
	if identityBefore != identityAfter {
		t.Fatalf("rotation changed profile identity")
	}
}
