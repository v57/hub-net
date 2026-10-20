package e2e

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/v57/hub-net-node/identity"
	protocol "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net/config"
	"github.com/v57/hub-net/hubconn"
	servicenetwork "github.com/v57/hub-net/hubconn/network"
	"github.com/v57/hub-net/profile"
	hubservice "github.com/v57/hub-service-go"
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

func restart(t *testing.T, hub *TestHub) {
	t.Helper()
	if err := hub.Restart(); err != nil {
		t.Fatalf("restart hub: %v", err)
	}
}

func hasPeer(s *agentSide, wireGuardKey string) bool {
	state, _ := s.agent.Adapter().State()
	for _, peer := range state.Peers {
		if base64.StdEncoding.EncodeToString(peer.PublicKey) == wireGuardKey {
			return true
		}
	}
	return false
}

// TestAgentE2ERevokedDeviceIsDropped revokes the caller's device: the hub
// host's agent drops its member peer and the firewall rules of its grant and
// refuses its grants from then on; revoking the provider makes the caller
// drop its outbound peer.
func TestAgentE2ERevokedDeviceIsDropped(t *testing.T) {
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
	waitFor(t, "device members", func() bool {
		return hub.RegistrationCount(providerMember) > 0 && hub.RegistrationCount(callerMember) > 0
	})
	provider.waitRegistered(t, "provider")
	caller.waitRegistered(t, "caller")
	callerWireGuard := base64.StdEncoding.EncodeToString(caller.agent.Profile().WireGuardPublicKey())
	providerWireGuard := base64.StdEncoding.EncodeToString(provider.agent.Profile().WireGuardPublicKey())

	// The hub host's agent (machine binding) keeps a peer per member. The
	// test hub sends member lists on subscribe, so reconnect the agents.
	restart(t, hub)
	waitFor(t, "member peer on the hub host", func() bool { return hasPeer(provider, callerWireGuard) })

	const port = 2222
	resourceID := provider.publishShare(t, "ssh", "tcp", port)
	caller.agent.SetResourceGeneration(resourceID, 1)
	provider.agent.SetResourceGeneration(resourceID, 1)
	candidates := []protocol.Candidate{{
		Version: protocol.WireVersion, CandidateID: "cand-revoke", SessionID: "sess-revoke",
		Key: providerMember, Kind: "host", Transport: "udp",
		Address: "198.51.100.41", Port: 51820, Priority: 100,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	}}
	grant, err := caller.agent.ConnectToShare(context.Background(), resourceID, "", candidates)
	if err != nil {
		t.Fatalf("ConnectToShare: %v", err)
	}
	if err := provider.agent.AuthorizeFlow(grant); err != nil {
		t.Fatalf("AuthorizeFlow: %v", err)
	}
	source := netip.MustParseAddr(grant.CallerAddress)
	destination := netip.MustParseAddr(grant.DestinationAddress)
	if !provider.backend.Allowed("tcp", source, destination, port, time.Now()) {
		t.Fatal("authorized flow not allowed")
	}

	hub.RevokeDevice(callerMember)
	restart(t, hub)
	waitFor(t, "revoked caller dropped", func() bool {
		return !hasPeer(provider, callerWireGuard) && !provider.backend.Allowed("tcp", source, destination, port, time.Now())
	})
	if err := provider.agent.AuthorizeFlow(grant); err == nil {
		t.Fatal("grant from a revoked device authorized")
	}
	if hasPeer(provider, callerWireGuard) {
		t.Fatal("revoked device reinstalled as a member peer")
	}

	if !hasPeer(caller, providerWireGuard) {
		t.Fatal("caller has no outbound peer to the provider")
	}
	hub.RevokeDevice(providerMember)
	restart(t, hub)
	waitFor(t, "caller drops the revoked provider", func() bool { return !hasPeer(caller, providerWireGuard) })
}

// startDeviceService connects a separate service certified by the device key
// at deviceKeyPath; it publishes shares through agent's socket.
func startDeviceService(t *testing.T, hub *TestHub, agent *agentSide, deviceKeyPath string) *hubconn.Service {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	device, err := hubservice.LoadDeviceKeyFile(deviceKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	service, err := hubconn.New(hubconn.Options{
		Identity: id, Address: hub.Port(), Name: "share-service", Device: device,
		NetworkOptions: servicenetwork.Options{AgentSocket: agent.cfg.AgentSocketPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Stop)
	key, _ := id.PublicKeyBase64()
	waitFor(t, "device-attached service connection", func() bool {
		for _, connect := range hub.Connects() {
			if connect.Key == key && connect.Device == device.ID() {
				return service.Sender() != nil
			}
		}
		return false
	})
	return service
}

// TestAgentE2ESharesFollowTheServiceDevice: a service's share is fronted by
// the agent on the service's own device, and refused through an agent on
// another device.
func TestAgentE2ESharesFollowTheServiceDevice(t *testing.T) {
	hub, err := NewDeviceTestHub()
	if err != nil {
		t.Fatalf("NewDeviceTestHub: %v", err)
	}
	defer hub.Close()
	devices := t.TempDir()
	hostKey := filepath.Join(devices, "host.key")
	host := startDeviceAgent(t, hub.Port(), "host", hostKey)
	member := "device:" + host.agent.DeviceID()
	waitFor(t, "host agent", func() bool { return hub.RegistrationCount(member) > 0 })
	host.waitRegistered(t, "host")

	local := startDeviceService(t, hub, host, hostKey)
	publications, err := local.PublishShare(context.Background(), "files", servicenetwork.ProtocolTCP, "127.0.0.1", 9100, nil)
	if err != nil {
		t.Fatalf("publish on the service's device: %v", err)
	}
	if len(publications) != 1 || publications[0].OverlayAddress != host.agent.Profile().Snapshot().OverlayAddress {
		t.Fatalf("publications = %+v", publications)
	}

	elsewhere := startDeviceService(t, hub, host, filepath.Join(devices, "other.key"))
	_, err = elsewhere.PublishShare(context.Background(), "files", servicenetwork.ProtocolTCP, "127.0.0.1", 9101, nil)
	if !errors.Is(err, servicenetwork.ErrShareDeviceMismatch) {
		t.Fatalf("publish through another device's agent: %v", err)
	}
}
