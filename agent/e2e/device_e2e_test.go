package e2e

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/v57/hub-net-node/identity"
	protocol "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net/config"
	"github.com/v57/hub-net/profile"
)

// startDeviceAgent starts an agent whose service key is certified by the
// device key at deviceKeyPath.
func startDeviceAgent(t *testing.T, hubPort int, name, deviceKeyPath string) *agentSide {
	t.Helper()
	return startAgentWithState(t, hubPort, name, t.TempDir(), func(cfg *config.Config) {
		cfg.DeviceKeyPath = deviceKeyPath
	})
}

// serviceKey reads the agent's service key from its identity file, which
// Prepare wrote before Run started.
func serviceKey(t *testing.T, s *agentSide) string {
	t.Helper()
	id, err := identity.Load(s.cfg.IdentityPath)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	key, err := id.PublicKeyBase64()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestAgentE2EDeviceMembers proves the agent joins as a device: it learns the
// hub key on a v0 connection that registers nothing, binds on the hub-bound
// device-attached connection, is listed as device:<id>, and connection grants
// naming device members verify on both sides.
func TestAgentE2EDeviceMembers(t *testing.T) {
	hub, err := NewDeviceTestHub()
	if err != nil {
		t.Fatalf("NewDeviceTestHub: %v", err)
	}
	defer hub.Close()

	devices := t.TempDir()
	provider := startDeviceAgent(t, hub.Port(), "provider", filepath.Join(devices, "provider.key"))
	caller := startDeviceAgent(t, hub.Port(), "caller", filepath.Join(devices, "caller.key"))
	providerMember := "device:" + provider.agent.DeviceID()
	callerMember := "device:" + caller.agent.DeviceID()
	if provider.agent.DeviceID() == "" || providerMember == callerMember {
		t.Fatalf("device ids: %q %q", provider.agent.DeviceID(), caller.agent.DeviceID())
	}
	providerService := serviceKey(t, provider)
	waitFor(t, "device members", func() bool {
		return hub.RegistrationCount(providerMember) > 0 && hub.RegistrationCount(callerMember) > 0
	})
	provider.waitRegistered(t, "provider")
	caller.waitRegistered(t, "caller")

	if hub.MemberKey(providerService) != providerMember || hub.RegistrationCount(providerService) != 0 {
		t.Fatalf("provider bound as %q (service-key binds %d)", hub.MemberKey(providerService), hub.RegistrationCount(providerService))
	}
	var versions []string
	for _, connect := range hub.Connects() {
		if connect.Key == providerService {
			versions = append(versions, connect.Version+":"+connect.Device)
		}
	}
	if len(versions) != 2 || versions[0] != "0:" || versions[1] != "1:"+provider.agent.DeviceID() {
		t.Fatalf("provider connects = %v, want a v0 key lookup then one v1 device connection", versions)
	}
	if got := provider.agent.HubService().HubKey(); got != hub.HubKey() {
		t.Fatalf("pinned hub key %q", got)
	}

	const shareName, port = "build-cache", 9000
	resourceID := provider.publishShare(t, shareName, "tcp", port)
	caller.agent.SetResourceGeneration(resourceID, 1)
	provider.agent.SetResourceGeneration(resourceID, 1)
	candidates := []protocol.Candidate{{
		Version: protocol.WireVersion, CandidateID: "cand-device", SessionID: "sess-device",
		Key: providerMember, Kind: "host", Transport: "udp",
		Address: "198.51.100.40", Port: 51820, Priority: 100,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	}}
	grant, err := caller.agent.ConnectToShare(context.Background(), resourceID, "", candidates)
	if err != nil {
		t.Fatalf("ConnectToShare: %v", err)
	}
	if grant.CallerKey != callerMember || grant.TargetKey != providerMember {
		t.Fatalf("grant keys %q → %q", grant.CallerKey, grant.TargetKey)
	}
	if err := provider.agent.AuthorizeFlow(grant); err != nil {
		t.Fatalf("AuthorizeFlow: %v", err)
	}
}

// TestAgentE2ESecondEndpointOnDeviceIsRefused shows a second agent (another
// service key) on a device that already has a network endpoint never binds.
func TestAgentE2ESecondEndpointOnDeviceIsRefused(t *testing.T) {
	hub, err := NewDeviceTestHub()
	if err != nil {
		t.Fatalf("NewDeviceTestHub: %v", err)
	}
	defer hub.Close()
	deviceKey := filepath.Join(t.TempDir(), "device.key")
	first := startDeviceAgent(t, hub.Port(), "first", deviceKey)
	member := "device:" + first.agent.DeviceID()
	waitFor(t, "first endpoint", func() bool { return hub.RegistrationCount(member) > 0 })
	first.waitRegistered(t, "first")

	second := startDeviceAgent(t, hub.Port(), "second", deviceKey)
	if second.agent.DeviceID() != first.agent.DeviceID() {
		t.Fatal("agents sharing a device key report different devices")
	}
	secondService := serviceKey(t, second)
	waitFor(t, "second agent's device connection", func() bool {
		for _, connect := range hub.Connects() {
			if connect.Key == secondService && connect.Device != "" {
				return true
			}
		}
		return false
	})
	time.Sleep(300 * time.Millisecond)
	if state := second.agent.Profile().State(); state == profile.StateRegistered {
		t.Fatal("second endpoint on one device registered")
	}
	if hub.RegistrationCount(member) != 1 || hub.MemberKey(secondService) != "" {
		t.Fatalf("binds %d, second bound as %q", hub.RegistrationCount(member), hub.MemberKey(secondService))
	}
}
