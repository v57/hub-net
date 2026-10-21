package invitation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/v57/hub-net-node/config"
	"github.com/v57/hub-net-node/identity"
	hubprotocol "github.com/v57/hub-net-node/models"
	nodeprotocol "github.com/v57/hub-net-node/protocol"
	"github.com/v57/hub-net-node/server"
	"github.com/v57/hub-net/nodeclient"
	"github.com/v57/hub-net/wireguard"
)

// hubProHostFixed is the inviter's overlay IPv4 inside the frozen overlay
// prefix; it doubles as the address where hub-server is reachable through the
// temporary link.
const hubProHostFixed = "100.96.0.1"

// runJoinNodeServer boots a real hub-net-node rendezvous server on a random
// loopback port. It serves both the WebSocket rendezvous and the UDP probe
// observation socket on the same address.
func runJoinNodeServer(t *testing.T) (address string, stop func()) {
	t.Helper()
	cfg := config.Defaults()
	cfg.StateDir = t.TempDir() + "/node-state"
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.NodeID = "join-test"
	if err := cfg.Resolve(); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()
	address = ""
	for i := 0; i < 100; i++ {
		if address = srv.ActualAddress(); address != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if address == "" {
		cancel()
		t.Fatal("server never bound")
	}
	return address, func() {
		cancel()
		select {
		case <-runErr:
		case <-time.After(3 * time.Second):
		}
	}
}

// inviterHarness is a registered online inviter: nodeclient registration,
// direct bootstrap handler, and the listener UDP socket that both probes the
// node and accepts framed joiner requests.
type inviterHarness struct {
	identity     *identity.Identity
	wireGuard    []byte
	adapter      *wireguard.FakeAdapter
	listener     *Listener
	listenerIP   string
	listenerPort uint16
	wgPort       uint16
	hubProHost   string
	stop         func()
}

func (h *inviterHarness) endpoints() []hubprotocol.BootstrapEndpoint {
	return []hubprotocol.BootstrapEndpoint{{
		Address: h.listenerIP, Port: h.wgPort, Transport: "udp",
	}}
}

// runInviter registers a real online inviter against the node at address.
// bindAddress selects the bootstrap listener bind; the default ":0" mirrors
// the production configuration (all interfaces, ephemeral port).
func runInviter(t *testing.T, nodeAddress, bindAddress string) *inviterHarness {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	wgPrivate := make([]byte, 32)
	if _, err := rand.Read(wgPrivate); err != nil {
		t.Fatal(err)
	}
	wgPublic, err := wireGuardPublicKey(wgPrivate)
	if err != nil {
		t.Fatal(err)
	}
	adapter := wireguard.NewFakeAdapter()
	if err := adapter.Up(wireguard.InterfaceConfig{
		Name: "hubnet0", Address: netip.MustParseAddr(hubProHostFixed), ListenPort: 51820,
	}); err != nil {
		t.Fatalf("inviter adapter Up: %v", err)
	}
	h := &inviterHarness{
		identity: id, wireGuard: wgPublic, adapter: adapter,
		wgPort: 51820, hubProHost: hubProHostFixed,
	}
	inviter, err := NewInviter(InviterOptions{
		Identity:     id,
		WireGuardKey: wgPublic,
		Adapter:      adapter,
		Endpoints:    h.endpoints,
		HubProHost:   func() string { return h.hubProHost },
	})
	if err != nil {
		t.Fatalf("NewInviter: %v", err)
	}
	listener, err := NewListener(ListenerOptions{Inviter: inviter, Address: bindAddress})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = listener.Run(ctx) }()
	h.listener = listener
	if address, ok := listener.Addr().(*net.UDPAddr); ok {
		h.listenerIP = address.IP.String()
		h.listenerPort = uint16(address.Port)
	} else {
		cancel()
		t.Fatal("listener did not bind")
	}
	client, err := nodeclient.New(nodeclient.Options{
		Endpoint: func() string { return nodeAddress },
		Identity: id,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Candidates: func() []hubprotocol.Candidate {
			return []hubprotocol.Candidate{{
				CandidateID: "inviter-bootstrap", Kind: "host", Transport: "udp",
				Address: h.listenerIP, Port: h.listenerPort, Priority: 100,
			}}
		},
		Probe: func(ctx context.Context, endpoint string, probe nodeprotocol.InvitationUDPProbe, expected string) error {
			return h.listener.Probe(ctx, endpoint, probe, expected)
		},
		Pending: func(tokenDigest, joinerKey string) {
			inviter.Expect(tokenDigest, joinerKey)
		},
		Bootstrap: func(nodeclient.BootstrapEvent) {},
	})
	if err != nil {
		cancel()
		t.Fatalf("nodeclient.New: %v", err)
	}
	go func() { _ = client.Run(ctx) }()
	online := false
	for i := 0; i < 100; i++ {
		if client.Online() {
			online = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !online {
		cancel()
		t.Fatal("inviter never registered")
	}
	h.stop = cancel
	return h
}

// fakeBinder records bind calls and returns a fixed membership.
type fakeBinder struct {
	mu     sync.Mutex
	calls  []bindCall
	result BindResult
	err    error
}

type bindCall struct {
	address      any
	wireGuardKey string
	name         string
	admission    hubprotocol.DirectBootstrapResponse
}

func (f *fakeBinder) Bind(_ context.Context, address any, _ *identity.Identity, wireGuardKey, name string, admission hubprotocol.DirectBootstrapResponse) (BindResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, bindCall{address: address, wireGuardKey: wireGuardKey, name: name, admission: admission})
	return f.result, f.err
}

func (f *fakeBinder) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newJoiner(t *testing.T) (*identity.Identity, []byte, *wireguard.FakeAdapter) {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal(err)
	}
	return id, privateKey, wireguard.NewFakeAdapter()
}

func TestJoinEndToEnd(t *testing.T) {
	nodeAddress, stopNode := runJoinNodeServer(t)
	defer stopNode()
	inviter := runInviter(t, nodeAddress, "127.0.0.1:0")
	defer inviter.stop()

	code, err := CreateCode(inviter.identity, "ws://"+nodeAddress)
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	joinerID, joinerWireGuard, adapter := newJoiner(t)
	binder := &fakeBinder{result: BindResult{
		HubKey: "hub-key", HubNetworkID: "hub-net-id",
		OverlayAddresses: []string{"100.96.0.2", "fd48:5542:4e45::2"},
		HeaderName:       "test-hub",
	}}

	result, err := Join(context.Background(), JoinOptions{
		Code: code, Identity: joinerID, WireGuardKey: joinerWireGuard,
		Adapter: adapter, Binder: binder, ListenPort: 51820,
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}

	if result.HubProHost != inviter.hubProHost {
		t.Errorf("HubProHost = %q, want %q", result.HubProHost, inviter.hubProHost)
	}
	if result.HubName != "test-hub" {
		t.Errorf("HubName = %q, want test-hub", result.HubName)
	}
	if result.InvitingKey != inviter.identityPublicKey(t) {
		t.Errorf("InvitingKey does not match inviter service key")
	}
	if result.HubKey != "hub-key" || result.HubNetworkID != "hub-net-id" {
		t.Errorf("bind membership not returned: %+v", result)
	}
	if len(result.OverlayAddresses) != 2 {
		t.Errorf("overlay addresses = %v", result.OverlayAddresses)
	}

	// The temporary link must be up with the joiner's bootstrap address and
	// the inviter peer covering the inviter addresses + hub-server.
	config, up := adapter.State()
	if !up {
		t.Fatal("joiner adapter not up after Join")
	}
	if config.Address.String() != result.JoinerAddress.IPv4 {
		t.Errorf("joiner address = %s, want %s", config.Address, result.JoinerAddress.IPv4)
	}
	if len(config.Peers) != 1 {
		t.Fatalf("joiner peers = %d, want 1", len(config.Peers))
	}
	peer := config.Peers[0]
	if got := string(peer.PublicKey); got != string(inviter.wireGuard) {
		t.Errorf("peer key mismatch")
	}
	if peer.Endpoint != net.JoinHostPort(inviter.listenerIP, "51820") {
		t.Errorf("peer endpoint = %q", peer.Endpoint)
	}
	wantAllowed := map[string]bool{
		result.InviterAddress.IPv4 + "/32":  true,
		result.InviterAddress.IPv6 + "/128": true,
		inviter.hubProHost + "/32":          true,
	}
	if len(peer.AllowedIPs) != len(wantAllowed) {
		t.Errorf("peer allowedIPs = %v", peer.AllowedIPs)
	}
	for _, prefix := range peer.AllowedIPs {
		if !wantAllowed[prefix.String()] {
			t.Errorf("unexpected allowedIP %s", prefix)
		}
	}

	// The binder must have received the hub-server address through the inviter
	// and the joiner's WireGuard key.
	binder.mu.Lock()
	defer binder.mu.Unlock()
	if len(binder.calls) != 1 {
		t.Fatalf("bind calls = %d, want 1", len(binder.calls))
	}
	if binder.calls[0].address != "ws://"+inviter.hubProHost+":1997" {
		t.Errorf("bind address = %v", binder.calls[0].address)
	}
	wgPublic, err := wireGuardPublicKey(joinerWireGuard)
	if err != nil {
		t.Fatal(err)
	}
	if binder.calls[0].wireGuardKey != base64Std(wgPublic) {
		t.Errorf("bind wireguard key mismatch")
	}
	// hub-server admits the joiner on the inviter's signed response, so the
	// binder must forward it unchanged.
	admission := binder.calls[0].admission
	if admission.JoinerWireGuardKey != base64Std(wgPublic) || admission.Signature == "" {
		t.Errorf("bind admission = %+v, want the signed response for this joiner", admission)
	}

	// The inviter must hold the temporary joiner peer for the assigned
	// point-to-point addresses.
	inviterState, inviterUp := inviter.adapter.State()
	if !inviterUp {
		t.Fatal("inviter adapter not up")
	}
	if len(inviterState.Peers) != 1 {
		t.Fatalf("inviter peers = %d, want 1", len(inviterState.Peers))
	}
	joinerWGPublic, err := wireGuardPublicKey(joinerWireGuard)
	if err != nil {
		t.Fatal(err)
	}
	inviterPeer := inviterState.Peers[0]
	if string(inviterPeer.PublicKey) != string(joinerWGPublic) {
		t.Errorf("inviter peer key mismatch")
	}
	wantInviterAllowed := map[string]bool{
		result.JoinerAddress.IPv4 + "/32":  true,
		result.JoinerAddress.IPv6 + "/128": true,
	}
	for _, prefix := range inviterPeer.AllowedIPs {
		if !wantInviterAllowed[prefix.String()] {
			t.Errorf("unexpected inviter allowedIP %s", prefix)
		}
	}
}

func (h *inviterHarness) identityPublicKey(t *testing.T) string {
	t.Helper()
	key, err := h.identity.PublicKeyBase64()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func base64Std(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func TestJoinInviterOffline(t *testing.T) {
	nodeAddress, stopNode := runJoinNodeServer(t)
	defer stopNode()
	// No inviter registers; the invitation is signed by an unknown key.
	offline, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	code, err := CreateCode(offline, "ws://"+nodeAddress)
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	joinerID, joinerWireGuard, adapter := newJoiner(t)

	_, err = Join(context.Background(), JoinOptions{
		Code: code, Identity: joinerID, WireGuardKey: joinerWireGuard,
		Adapter: adapter, Binder: &fakeBinder{}, ListenPort: 51820,
	})
	if err == nil {
		t.Fatal("Join succeeded with no online inviter")
	}
	if !strings.Contains(err.Error(), "inviter offline") {
		t.Errorf("error = %v, want inviter offline rejection", err)
	}
	if _, up := adapter.State(); up {
		t.Error("adapter left up after failed join")
	}
}

func TestJoinReplaySingleUse(t *testing.T) {
	nodeAddress, stopNode := runJoinNodeServer(t)
	defer stopNode()
	inviter := runInviter(t, nodeAddress, "127.0.0.1:0")
	defer inviter.stop()

	code, err := CreateCode(inviter.identity, "ws://"+nodeAddress)
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}

	first := &fakeBinder{result: BindResult{
		HubKey: "hub-key", HubNetworkID: "net",
		OverlayAddresses: []string{"100.96.0.2", "fd48:5542:4e45::2"},
		HeaderName:       "hub",
	}}
	joinerID, joinerWireGuard, adapter := newJoiner(t)
	if _, err := Join(context.Background(), JoinOptions{
		Code: code, Identity: joinerID, WireGuardKey: joinerWireGuard,
		Adapter: adapter, Binder: first, ListenPort: 51820,
	}); err != nil {
		t.Fatalf("first join: %v", err)
	}

	// A second joiner with the same invitation must be rejected at the node:
	// the joiner's session.open consumes the global single-use slot.
	secondID, secondWireGuard, secondAdapter := newJoiner(t)
	_, err = Join(context.Background(), JoinOptions{
		Code: code, Identity: secondID, WireGuardKey: secondWireGuard,
		Adapter: secondAdapter, Binder: &fakeBinder{}, ListenPort: 51820,
	})
	if err == nil {
		t.Fatal("second join with same invitation succeeded")
	}
	if !strings.Contains(err.Error(), "replay") {
		t.Errorf("error = %v, want replay rejection", err)
	}
	if _, up := secondAdapter.State(); up {
		t.Error("adapter left up after replay rejection")
	}
}

func TestJoinRejectsInvalidInvitation(t *testing.T) {
	joinerID, joinerWireGuard, adapter := newJoiner(t)
	_, err := Join(context.Background(), JoinOptions{
		Code: "not-an-invitation", Identity: joinerID, WireGuardKey: joinerWireGuard,
		Adapter: adapter, Binder: &fakeBinder{},
	})
	if err == nil {
		t.Fatal("Join accepted a malformed invitation")
	}
}

func TestNodeEndpoints(t *testing.T) {
	wsURL, udp, err := nodeEndpoints("https://localhost/node")
	if err != nil {
		t.Fatal(err)
	}
	if wsURL != "wss://localhost/node/rendezvous" {
		t.Errorf("wsURL = %q", wsURL)
	}
	if udp.Port != 443 || !strings.HasSuffix(udp.String(), ":443") {
		t.Errorf("udp = %q, want port 443", udp)
	}

	wsURL, udp, err = nodeEndpoints("ws://127.0.0.1:1964")
	if err != nil {
		t.Fatal(err)
	}
	if wsURL != "ws://127.0.0.1:1964/rendezvous" {
		t.Errorf("wsURL = %q", wsURL)
	}
	if udp.String() != "127.0.0.1:1964" {
		t.Errorf("udp = %q", udp)
	}
}

func TestInviterPeerRoundTrip(t *testing.T) {
	result := JoinResult{
		InviterWireGuardKey: make([]byte, 32),
		Endpoint:            "127.0.0.1:51820",
		InviterAddress:      hubprotocol.BootstrapAddress{IPv4: "100.127.254.1", IPv6: "fd48:5542:4e45:fffe::1"},
		HubProHost:          "100.96.0.1",
	}
	for i := range result.InviterWireGuardKey {
		result.InviterWireGuardKey[i] = byte(i)
	}
	path := filepath.Join(t.TempDir(), InviterPeerFileName)
	if err := SaveInviterPeer(path, NewInviterPeer(result)); err != nil {
		t.Fatalf("SaveInviterPeer: %v", err)
	}
	peers, err := LoadInviterPeers(path)
	if err != nil {
		t.Fatalf("LoadInviterPeers: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(peers))
	}
	peer := peers[0]
	if string(peer.PublicKey) != string(result.InviterWireGuardKey) {
		t.Error("peer public key mismatch")
	}
	if peer.Endpoint != result.Endpoint {
		t.Errorf("peer endpoint = %q", peer.Endpoint)
	}
	want := map[string]bool{
		"100.127.254.1/32":           true,
		"fd48:5542:4e45:fffe::1/128": true,
		"100.96.0.1/32":              true,
	}
	for _, prefix := range peer.AllowedIPs {
		if !want[prefix.String()] {
			t.Errorf("unexpected allowedIP %s", prefix)
		}
		delete(want, prefix.String())
	}
	if len(want) != 0 {
		t.Errorf("missing allowedIPs %v", want)
	}
}

func TestLoadInviterPeersAbsent(t *testing.T) {
	peers, err := LoadInviterPeers(filepath.Join(t.TempDir(), InviterPeerFileName))
	if err != nil {
		t.Fatalf("LoadInviterPeers: %v", err)
	}
	if peers != nil {
		t.Errorf("peers = %v, want nil", peers)
	}
}

func TestInviterPeerRejectsBadKey(t *testing.T) {
	peer := InviterPeer{Version: inviterPeerVersion, PublicKey: "not-base64", Endpoint: "x:1"}
	if _, err := peer.PeerConfig(); err == nil {
		t.Fatal("PeerConfig accepted a bad public key")
	}
}

// TestJoinEndToEndAllInterfacesListener exercises the production listener
// configuration: the bootstrap listener binds all interfaces (":0"), so its
// declared candidate and response endpoint carry an unspecified address and
// the joiner must fall back to the node-observed endpoint for both the direct
// exchange and the WireGuard peer endpoint.
func TestJoinEndToEndAllInterfacesListener(t *testing.T) {
	nodeAddress, stopNode := runJoinNodeServer(t)
	defer stopNode()
	inviter := runInviter(t, nodeAddress, ":0")
	defer inviter.stop()
	if parsed, err := netip.ParseAddr(inviter.listenerIP); err == nil && !parsed.IsUnspecified() {
		t.Fatalf("listener bound a usable address %q; test fixture broken", inviter.listenerIP)
	}

	code, err := CreateCode(inviter.identity, "ws://"+nodeAddress)
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	joinerID, joinerWireGuard, adapter := newJoiner(t)
	binder := &fakeBinder{result: BindResult{
		HubKey: "hub-key", HubNetworkID: "net",
		OverlayAddresses: []string{"100.96.0.2", "fd48:5542:4e45::2"},
		HeaderName:       "hub",
	}}
	result, err := Join(context.Background(), JoinOptions{
		Code: code, Identity: joinerID, WireGuardKey: joinerWireGuard,
		Adapter: adapter, Binder: binder, ListenPort: 51820,
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	config, up := adapter.State()
	if !up || len(config.Peers) != 1 {
		t.Fatalf("temp link not configured: up=%v peers=%d", up, len(config.Peers))
	}
	// The WG endpoint must combine the node-observed address (the listener
	// socket's real source, loopback here) with the advertised WireGuard port.
	if config.Peers[0].Endpoint != "127.0.0.1:51820" {
		t.Errorf("peer endpoint = %q, want 127.0.0.1:51820", config.Peers[0].Endpoint)
	}
	_ = result
}

// blockingBinder never returns; the join must fail when its budget expires
// instead of hanging with the temporary link up.
type blockingBinder struct{}

func (blockingBinder) Bind(ctx context.Context, _ any, _ *identity.Identity, _, _ string, _ hubprotocol.DirectBootstrapResponse) (BindResult, error) {
	<-ctx.Done()
	return BindResult{}, ctx.Err()
}

func TestJoinBindTimeout(t *testing.T) {
	nodeAddress, stopNode := runJoinNodeServer(t)
	defer stopNode()
	inviter := runInviter(t, nodeAddress, "127.0.0.1:0")
	defer inviter.stop()

	code, err := CreateCode(inviter.identity, "ws://"+nodeAddress)
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	joinerID, joinerWireGuard, adapter := newJoiner(t)
	start := time.Now()
	_, err = Join(context.Background(), JoinOptions{
		Code: code, Identity: joinerID, WireGuardKey: joinerWireGuard,
		Adapter: adapter, Binder: blockingBinder{}, ListenPort: 51820,
		Timeout: 500 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Join succeeded with a blocking binder")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("join took %v, want bounded by Timeout", elapsed)
	}
	// The temporary link must be torn down on bind failure.
	if _, up := adapter.State(); up {
		t.Error("adapter left up after bind failure")
	}
}
