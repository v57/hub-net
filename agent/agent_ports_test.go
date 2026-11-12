package hubnet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/v57/hub-net-node/models"

	"github.com/v57/hub-net/config"
	"github.com/v57/hub-net/deviceports"
	"github.com/v57/hub-net/enforcement"
	"github.com/v57/hub-net/peerlink"
	"github.com/v57/hub-net/wireguard"
)

// A Hub-signed grant is everything a Hub can say about this device: a peer, its
// addresses and the ports to open. The grant here verifies; the device's own
// list still decides.
func signedLinkGrant(t *testing.T, ports ...models.PeerLinkPort) (peerlink.Peer, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	hubKey := base64.StdEncoding.EncodeToString(der)
	now := time.Now()
	grant := models.PeerLinkGrant{
		Version: models.WireVersion, GrantID: "grant-1", HubKey: hubKey, HubNetworkID: "network",
		Purpose: models.PeerLinkPurposeShare,
		A:       models.PeerLinkSide{Key: "operator", WireGuardKey: "wg-operator", Member: "operator", Addresses: []string{"100.96.0.9"}},
		B:       models.PeerLinkSide{Key: "device", WireGuardKey: "wg-device", Member: "device", Addresses: []string{"100.96.0.3"}},
		AViaB:   []string{"100.96.0.3/32"}, BViaA: []string{"100.96.0.9/32"},
		AToB: ports, BToA: []models.PeerLinkPort{},
		IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	grant.Signature, err = models.SignEnvelope(models.PurposePeerLink, grant, private)
	if err != nil {
		t.Fatal(err)
	}
	link, err := peerlink.Verify(grant, hubKey, "device", now)
	if err != nil {
		t.Fatalf("the grant should verify: %v", err)
	}
	sources := make([]netip.Addr, 0, len(link.Routes))
	for _, route := range link.Routes {
		sources = append(sources, route.Addr())
	}
	return peerlink.Peer{Key: link.Other.Key, WireGuardKey: link.Other.WireGuardKey, Routes: link.Routes, Sources: sources, Ports: link.Exposed}, hubKey
}

func portsAgent(t *testing.T) (*Agent, *enforcement.MemoryBackend) {
	t.Helper()
	backend := &enforcement.MemoryBackend{}
	manager, err := enforcement.New(backend)
	if err != nil {
		t.Fatal(err)
	}
	list, err := deviceports.Open(filepath.Join(t.TempDir(), DevicePortsFile))
	if err != nil {
		t.Fatal(err)
	}
	return &Agent{
		enforcementMgr: manager, devicePorts: list, logger: slog.Default(), bindingKind: models.LocalAgentBindingJoin,
		interfaceAddress: netip.MustParseAddr("100.96.0.3"),
	}, backend
}

var (
	operatorAddress = netip.MustParseAddr("100.96.0.9")
	deviceAddress   = netip.MustParseAddr("100.96.0.3")
)

func TestAHubSignedGrantCantOpenPort22OnADeviceThatHasntEnabledIt(t *testing.T) {
	agent, backend := portsAgent(t)
	peer, _ := signedLinkGrant(t, models.PeerLinkPort{Protocol: "tcp", Port: 22})
	if err := agent.applyLinkPorts([]peerlink.Peer{peer}); err != nil {
		t.Fatal(err)
	}
	if backend.Allowed("tcp", operatorAddress, deviceAddress, 22, time.Now()) {
		t.Fatal("a Hub-signed grant opened SSH on a device that hasn't enabled it")
	}
	if err := agent.devicePorts.SetSSH(true, 0); err != nil {
		t.Fatal(err)
	}
	if err := agent.applyLinkPorts([]peerlink.Peer{peer}); err != nil {
		t.Fatal(err)
	}
	if !backend.Allowed("tcp", operatorAddress, deviceAddress, 22, time.Now()) {
		t.Fatal("SSH stayed closed after the user enabled it")
	}
	if err := agent.devicePorts.SetSSH(false, 0); err != nil {
		t.Fatal(err)
	}
	if err := agent.applyLinkPorts([]peerlink.Peer{peer}); err != nil {
		t.Fatal(err)
	}
	if backend.Allowed("tcp", operatorAddress, deviceAddress, 22, time.Now()) {
		t.Fatal("SSH stayed open after the user turned it off")
	}
	if got := backend.Terminated(); len(got) == 0 {
		t.Fatal("turning SSH off left its flows")
	}
}

func TestADeviceOpensItsOwnSharesAHubNamesAndNothingElse(t *testing.T) {
	agent, backend := portsAgent(t)
	if err := agent.devicePorts.NoteAttested(deviceports.Port{Protocol: "tcp", Port: 8554}); err != nil {
		t.Fatal(err)
	}
	peer, _ := signedLinkGrant(t, models.PeerLinkPort{Protocol: "tcp", Port: 8554}, models.PeerLinkPort{Protocol: "tcp", Port: 9000})
	if err := agent.applyLinkPorts([]peerlink.Peer{peer}); err != nil {
		t.Fatal(err)
	}
	if !backend.Allowed("tcp", operatorAddress, deviceAddress, 8554, time.Now()) {
		t.Fatal("an attested share stopped working")
	}
	if backend.Allowed("tcp", operatorAddress, deviceAddress, 9000, time.Now()) {
		t.Fatal("the Hub widened past the device's list")
	}
	// A Hub can narrow: a grant that no longer names the share closes it
	narrowed, _ := signedLinkGrant(t)
	if err := agent.applyLinkPorts([]peerlink.Peer{narrowed}); err != nil {
		t.Fatal(err)
	}
	if backend.Allowed("tcp", operatorAddress, deviceAddress, 8554, time.Now()) {
		t.Fatal("a port the Hub stopped naming stayed open")
	}
}

func TestAConnectionGrantForAPortOffTheListIsRefused(t *testing.T) {
	agent, backend := portsAgent(t)
	agent.netUsers = nil
	err := agent.AuthorizeFlow(models.ConnectionGrant{
		CallerAddress: operatorAddress.String(), DestinationAddress: deviceAddress.String(), Protocol: "tcp",
		DestinationPort: 22, ResourceID: "resource", ProviderID: "provider",
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	})
	if err != errPortNotAllowed {
		t.Fatalf("AuthorizeFlow = %v", err)
	}
	if backend.Allowed("tcp", operatorAddress, deviceAddress, 22, time.Now()) {
		t.Fatal("the grant opened the port")
	}
}

func TestThePresenceSecretStaysInAFileOnlyTheOwnerReads(t *testing.T) {
	a := &Agent{config: config.Config{StateDir: t.TempDir()}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	secret := bytes.Repeat([]byte{5}, 32)
	a.setPresenceSecret(base64.StdEncoding.EncodeToString(secret))
	if !bytes.Equal(a.loadPresenceSecret(), secret) {
		t.Fatal("not read back")
	}
	// Windows has no mode bits: the daemon makes the state directory private
	// (SYSTEM and Administrators only), which the file inherits.
	if info, err := os.Stat(a.presenceSecretPath()); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", info, err)
	}
	// A Hub with no secret: the device goes back to answering everyone, and the file goes
	a.setPresenceSecret("")
	if _, err := os.Stat(a.presenceSecretPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("still there: %v", err)
	}
	a.setPresenceSecret("not base64!")
	if a.loadPresenceSecret() != nil {
		t.Fatal("kept an unreadable secret")
	}
}

// The link manager reads WireGuard's own endpoint for a peer (H-032): the
// profile's endpoint for the hub's machine until a link or the peer's packets
// move it.
func TestLiveEndpointIsWireGuardsEndpointForThePeer(t *testing.T) {
	adapter := wireguard.NewFakeAdapter()
	key := bytes.Repeat([]byte{7}, 32)
	if err := adapter.Up(wireguard.InterfaceConfig{Name: "hubnet0", Peers: []wireguard.PeerConfig{{
		PublicKey: key, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32")}, Endpoint: "[::ffff:192.168.1.6]:51820",
	}}}); err != nil {
		t.Fatal(err)
	}
	a := &Agent{adapter: adapter}
	if endpoint, ok := a.liveEndpoint(base64.StdEncoding.EncodeToString(key)); !ok || endpoint != "192.168.1.6:51820" {
		t.Fatalf("live endpoint = %q (%v), want 192.168.1.6:51820", endpoint, ok)
	}
	if endpoint, ok := a.liveEndpoint(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))); ok {
		t.Fatalf("a peer WireGuard doesn't have has endpoint %q", endpoint)
	}
}
