package profile

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/v57/hub-service-go/identity"
	"github.com/v57/hub-service-go/protocol"
)

func mustRegistrar(t *testing.T) (*Profile, *Registrar) {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	prof, err := New(id)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wg := make([]byte, 32)
	for i := range wg {
		wg[i] = byte(i + 1)
	}
	prof.SetWireGuardPublicKey(wg)
	reg, err := NewRegistrar(RegistrarOptions{
		Profile: prof,
		Key:     "agent-key-base64",
		Name:    "hub-net",
	})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	return prof, reg
}

func TestRegisterBodyShape(t *testing.T) {
	prof, reg := mustRegistrar(t)
	body, err := reg.RegisterBody()
	if err != nil {
		t.Fatalf("RegisterBody: %v", err)
	}
	if body.Version != protocol.WireVersion {
		t.Fatalf("version = %d, want %d", body.Version, protocol.WireVersion)
	}
	_ = prof.Snapshot()
	decoded, err := base64.StdEncoding.DecodeString(body.WireGuardKey)
	if err != nil {
		t.Fatalf("wireGuardKey not base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("wireGuardKey length = %d", len(decoded))
	}
	if body.ConnectedAt == "" {
		t.Fatalf("connectedAt empty")
	}
	if _, err := time.Parse(time.RFC3339Nano, body.ConnectedAt); err != nil {
		t.Fatalf("connectedAt not RFC3339: %v", err)
	}
}

func TestRegisterRejectsNilSender(t *testing.T) {
	_, reg := mustRegistrar(t)
	if err := reg.Register(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "sender") {
		t.Fatalf("err = %v, want sender error", err)
	}
}

func TestRegistrarRequiresProfileAndKey(t *testing.T) {
	if _, err := NewRegistrar(RegistrarOptions{Key: "x"}); err == nil {
		t.Fatalf("expected error without profile")
	}
	if _, err := NewRegistrar(RegistrarOptions{Profile: &Profile{}}); err == nil {
		t.Fatalf("expected error without agent key")
	}
}

func TestOnConnectReturnsCallback(t *testing.T) {
	_, reg := mustRegistrar(t)
	cb := reg.OnConnect()
	if cb == nil {
		t.Fatalf("OnConnect returned nil")
	}
	// Calling with a nil sender exercises the guard inside Register without
	// panicking.
	cb(nil)
}
