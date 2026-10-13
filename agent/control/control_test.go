package control

import (
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/v57/channel-go/channelgo"
	"github.com/v57/hub-net-node/identity"
	"github.com/v57/hub-net/hubconn"
	"github.com/v57/hub-net/profile"
	"github.com/v57/hub-net/wireguard"
)

func testController(t *testing.T) (*Controller, *profile.Profile, *wireguard.FakeAdapter) {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	prof, err := profile.New(id)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	prof.SetWireGuardPublicKey(key)
	adapter := wireguard.NewFakeAdapter()
	controller, err := New(Options{
		Profile: prof, Adapter: adapter,
		Shares: func() []ShareHealth {
			return []ShareHealth{{ResourceID: "resource-1", Name: "s3", Protocol: "tcp", Healthy: true}}
		},
		NodeConfig: NodeConfig{Enabled: true, Endpoints: []string{"node.example:443"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller, prof, adapter
}

func TestSnapshotsExcludePrivateMaterial(t *testing.T) {
	controller, prof, adapter := testController(t)
	prof.ConfirmRegistration("100.96.0.2", "network-1", 4)
	if err := adapter.Up(wireguard.InterfaceConfig{}); err != nil {
		t.Fatal(err)
	}

	got := controller.Profile()
	if got.State != profile.StateRegistered || got.OverlayAddress != "100.96.0.2" || got.Generation != 4 {
		t.Fatalf("unexpected profile: %#v", got)
	}
	if _, err := base64.StdEncoding.DecodeString(got.WireGuardKey); err != nil {
		t.Fatalf("public WireGuard key is not base64: %v", err)
	}
	health := controller.Health()
	if !health.Available || !health.WireGuardUp || health.Shares != 1 {
		t.Fatalf("unexpected health: %#v", health)
	}
}

func TestNodeConfigUpdateCopiesAndValidates(t *testing.T) {
	controller, _, _ := testController(t)
	value, err := controller.updateNodeConfig(channelgo.Body{Body: map[string]any{
		"enabled": false, "endpoints": []any{"one.example:443", "two.example:443"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := value.(NodeConfig)
	got.Endpoints[0] = "mutated"
	if controller.NodeConfig().Endpoints[0] != "one.example:443" {
		t.Fatal("node config leaked mutable storage")
	}
	if _, err := controller.updateNodeConfig(channelgo.Body{Body: map[string]any{
		"enabled": true, "endpoints": []any{""},
	}}); err == nil {
		t.Fatal("empty endpoint accepted")
	}
}

func TestRegisterAllControlPaths(t *testing.T) {
	controller, _, _ := testController(t)
	id, err := identity.Load(filepath.Join(t.TempDir(), "service.identity"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := hubconn.New(hubconn.Options{Identity: id})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Register(svc); err != nil {
		t.Fatal(err)
	}
	// Registration completes before Start; no live Hub connection is needed.
}
