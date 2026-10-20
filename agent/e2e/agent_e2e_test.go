package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/v57/channel-go/channelgo"
	hubnet "github.com/v57/hub-net"
	"github.com/v57/hub-net-node/identity"
	protocol "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net/config"
	"github.com/v57/hub-net/enforcement"
	"github.com/v57/hub-net/hubconn"
	servicenetwork "github.com/v57/hub-net/hubconn/network"
	"github.com/v57/hub-net/profile"
	"github.com/v57/hub-net/wireguard"
)

// agentSide wraps a running hubnet.Agent plus the helpers the agent-level
// harness needs to drive it: the agent itself, its enforcement backend, its
// IPC socket, and its Hub service identity.
type agentSide struct {
	agent   *hubnet.Agent
	backend *enforcement.MemoryBackend
	cfg     config.Config
	cancel  context.CancelFunc
	done    chan struct{}
	stop    sync.Once
}

// startAgent builds a hubnet.Agent rooted at a temp state dir, pointed at the
// test Hub, with deterministic test doubles injected: FakeAdapter (no kernel
// WireGuard), always-OK candidate + handshake checkers (the harness asserts
// the authorization chain, not transport reachability — that is HN-308), and
// enforcement.MemoryBackend (no nftables/privilege). Run is launched in a
// goroutine; the returned cleanup cancels and waits.
func startAgent(t *testing.T, hubPort int, name string) *agentSide {
	t.Helper()
	return startAgentWithState(t, hubPort, name, t.TempDir())
}

// startAgentWithState starts an agent using a caller-owned persistent state
// directory. Tests can stop it and construct a replacement process over the
// same identity and WireGuard key files.
func startAgentWithState(t *testing.T, hubPort int, name, stateDir string, configure ...func(*config.Config)) *agentSide {
	t.Helper()
	cfg := config.Defaults()
	cfg.StateDir = stateDir
	cfg.IdentityPath = cfg.StateDir + "/" + config.DefaultIdentityFile
	cfg.WireGuardKeyPath = cfg.StateDir + "/" + config.DefaultWireGuardKeyFile
	cfg.AgentSocketPath = shortSocketPath(t, name)
	cfg.HubAddress = hubPort
	cfg.HandshakeTimeout = 2 * time.Second
	cfg.PeerIdleTimeout = 5 * time.Minute
	for _, change := range configure {
		change(&cfg)
	}

	backend := &enforcement.MemoryBackend{}
	agent, err := hubnet.New(hubnet.Options{
		Config:             cfg,
		Adapter:            wireguard.NewFakeAdapter(),
		CandidateChecker:   alwaysOKCandidateAgent{},
		HandshakeChecker:   alwaysOKHandshakeAgent{},
		EnforcementBackend: backend,
	})
	if err != nil {
		t.Fatalf("%s New: %v", name, err)
	}
	// Prepare synchronously so the profile, adapter, and IPC server are fully
	// constructed before Run launches. The accessors (Profile, Adapter,
	// HubService) read these fields without a lock; Prepare-before-Run is the
	// documented contract that keeps those reads race-free.
	if err := agent.Prepare(context.Background()); err != nil {
		t.Fatalf("%s Prepare: %v", name, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		errCh <- agent.Run(ctx)
		close(done)
	}()
	side := &agentSide{
		agent: agent, backend: backend, cfg: cfg,
		cancel: cancel, done: done,
	}
	// Wait for the IPC server to come up so callers can reach the agent.
	if err := waitForSocket(cfg.AgentSocketPath, 3*time.Second); err != nil {
		cancel()
		t.Fatalf("%s wait socket: %v", name, err)
	}
	t.Cleanup(func() { side.stopAgent(t, name) })
	return side
}

func (s *agentSide) stopAgent(t *testing.T, name string) {
	t.Helper()
	s.stop.Do(func() { s.cancel() })
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		t.Errorf("%s agent did not stop", name)
	}
}

// waitRegistered polls the agent profile until it reaches StateRegistered or
// the timeout elapses, then brings the FakeAdapter up on the Hub-assigned
// overlay address. The real platform adapter is brought up by HN-311 packaging
// after registration; the harness does the equivalent on the fake so installed
// peers are observable through Adapter().State().
func (s *agentSide) waitRegistered(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.agent.Profile() != nil && s.agent.Profile().State() == profile.StateRegistered {
			s.bringAdapterUp(t, name)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s agent did not register within timeout", name)
}

func (s *agentSide) bringAdapterUp(t *testing.T, name string) {
	t.Helper()
	snap := s.agent.Profile().Snapshot()
	if snap.OverlayAddress == "" {
		t.Fatalf("%s registered without overlay address", name)
	}
	addr, err := netip.ParseAddr(snap.OverlayAddress)
	if err != nil {
		t.Fatalf("%s overlay address %s: %v", name, snap.OverlayAddress, err)
	}
	wgPub := s.agent.Profile().WireGuardPublicKey()
	_ = wgPub // FakeAdapter records but does not validate the key material
	// The agent owns the real WireGuard private key in keychain storage and
	// does not expose it. The FakeAdapter only echoes InterfaceConfig for test
	// assertions, so a placeholder private key is sufficient here; real
	// platform adapters (HN-303) read the persisted key directly.
	wgPriv := make([]byte, 32)
	adapter, ok := s.agent.Adapter().(*wireguard.FakeAdapter)
	if !ok {
		t.Fatalf("%s adapter is not FakeAdapter", name)
	}
	if err := adapter.Up(wireguard.InterfaceConfig{
		Name: "hubnet-" + name, PrivateKey: wgPriv,
		Address: addr, ListenPort: 51820,
	}); err != nil {
		t.Fatalf("%s adapter Up: %v", name, err)
	}
}

// publishShare drives the production attestation + share-registration path for
// the agent's profile:
//  1. obtain a signed AgentAttestation from the agent's own IPC server
//     (/challenge then /attest), signing the nonce with the agent's Hub
//     identity exactly as the hubconn/network Publisher does;
//  2. send network/shares/replace through the agent's Hub sender with the
//     attestation embedded, exactly as the Publisher does.
//
// Returns the stable resourceId the Hub assigned.
func (s *agentSide) publishShare(t *testing.T, name, proto string, port uint16) string {
	t.Helper()
	hub := s.agent.HubService()
	if hub == nil {
		t.Fatalf("%s publish: hub service not started", name)
	}
	id := hub.Identity()
	att := agentSelfAttestation(t, s.cfg.AgentSocketPath, id, name, proto, "127.0.0.1", port)
	sender := hub.Sender()
	if sender == nil {
		t.Fatalf("%s publish: hub sender not connected", name)
	}
	share := map[string]any{
		"version":     protocol.WireVersion,
		"name":        name,
		"protocol":    proto,
		"target":      map[string]any{"host": "127.0.0.1", "port": port},
		"policy":      map[string]any{"mode": "hub"},
		"attestation": att,
	}
	body := map[string]any{"shares": []any{share}}
	resp, err := channelgo.Send[map[string]any](sender, "network/shares/replace", body)
	if err != nil {
		t.Fatalf("%s shares/replace: %v", name, err)
	}
	publications, _ := resp["shares"].([]any)
	if len(publications) != 1 {
		t.Fatalf("%s shares/replace returned %d publications, want 1: %v", name, len(publications), resp)
	}
	first, _ := publications[0].(map[string]any)
	rid, _ := first["resourceId"].(string)
	if rid == "" {
		t.Fatalf("%s shares/replace returned empty resourceId: %v", name, first)
	}
	return rid
}

// TestAgentE2EAuthorizedTCPShare wires two real hubnet.Agent processes against
// an in-process Hub and proves the full caller→provider TCP authorization
// chain through the agent's public API: ConnectToShare requests the grant and
// installs the peer; AuthorizeFlow installs the firewall rule; the
// enforcement backend admits exactly the signed tuple.
func TestAgentE2EAuthorizedTCPShare(t *testing.T) {
	hub, err := NewTestHub()
	if err != nil {
		t.Fatalf("NewTestHub: %v", err)
	}
	defer hub.Close()

	provider := startAgent(t, hub.Port(), "provider")
	caller := startAgent(t, hub.Port(), "caller")
	provider.waitRegistered(t, "provider")
	caller.waitRegistered(t, "caller")

	const (
		shareName = "minecraft"
		tcpPort   = 25565
	)
	resourceID := provider.publishShare(t, shareName, "tcp", tcpPort)
	caller.agent.SetResourceGeneration(resourceID, 1)
	provider.agent.SetResourceGeneration(resourceID, 1)

	candidates := []protocol.Candidate{{
		Version: protocol.WireVersion, CandidateID: "cand-tcp", SessionID: "sess-tcp",
		Key: providerKey(t, provider), Kind: "host", Transport: "udp",
		Address: "198.51.100.30", Port: 51820, Priority: 100,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	}}
	grant, err := caller.agent.ConnectToShare(context.Background(), resourceID, "", candidates)
	if err != nil {
		t.Fatalf("ConnectToShare: %v", err)
	}

	// Caller side: peer installed with provider key + destination /32 only.
	state, _ := caller.agent.Adapter().(*wireguard.FakeAdapter).State()
	if len(state.Peers) != 1 {
		t.Fatalf("caller peers = %d, want 1", len(state.Peers))
	}
	peer := state.Peers[0]
	if got := base64.StdEncoding.EncodeToString(peer.PublicKey); got != grant.TargetWireGuardKey {
		t.Fatalf("peer key = %s, want grant target key", got)
	}
	wantDest, _ := netip.ParseAddr(grant.DestinationAddress)
	if len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0] != netip.PrefixFrom(wantDest, 32) {
		t.Fatalf("peer allowed = %v, want [%s/32]", peer.AllowedIPs, wantDest)
	}

	// Provider side: enforcement admits the signed tuple, rejects scans.
	if err := provider.agent.AuthorizeFlow(grant); err != nil {
		t.Fatalf("AuthorizeFlow: %v", err)
	}
	now := time.Now()
	source, _ := netip.ParseAddr(grant.CallerAddress)
	dest, _ := netip.ParseAddr(grant.DestinationAddress)
	if !provider.backend.Allowed("tcp", source, dest, tcpPort, now) {
		t.Fatal("provider denied authorized TCP tuple")
	}
	if provider.backend.Allowed("tcp", source, dest, tcpPort+1, now) {
		t.Fatal("provider admitted unshared port")
	}
	if provider.backend.Allowed("udp", source, dest, tcpPort, now) {
		t.Fatal("provider admitted UDP against TCP share")
	}
}

// TestAgentE2EAuthorizedUDPShare repeats the TCP chain for a UDP share,
// proving the protocol field threads through ConnectToShare → grant →
// AuthorizeFlow without crossing protocols.
func TestAgentE2EAuthorizedUDPShare(t *testing.T) {
	hub, err := NewTestHub()
	if err != nil {
		t.Fatalf("NewTestHub: %v", err)
	}
	defer hub.Close()

	provider := startAgent(t, hub.Port(), "provider")
	caller := startAgent(t, hub.Port(), "caller")
	provider.waitRegistered(t, "provider")
	caller.waitRegistered(t, "caller")

	const (
		shareName = "voice"
		udpPort   = 41200
	)
	resourceID := provider.publishShare(t, shareName, "udp", udpPort)
	caller.agent.SetResourceGeneration(resourceID, 1)
	provider.agent.SetResourceGeneration(resourceID, 1)

	candidates := []protocol.Candidate{{
		Version: protocol.WireVersion, CandidateID: "cand-udp", SessionID: "sess-udp",
		Key: providerKey(t, provider), Kind: "host", Transport: "udp",
		Address: "198.51.100.30", Port: 51820, Priority: 100,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	}}
	grant, err := caller.agent.ConnectToShare(context.Background(), resourceID, "", candidates)
	if err != nil {
		t.Fatalf("ConnectToShare: %v", err)
	}
	if grant.Protocol != "udp" {
		t.Fatalf("grant protocol = %s, want udp", grant.Protocol)
	}
	if err := provider.agent.AuthorizeFlow(grant); err != nil {
		t.Fatalf("AuthorizeFlow: %v", err)
	}
	now := time.Now()
	source, _ := netip.ParseAddr(grant.CallerAddress)
	dest, _ := netip.ParseAddr(grant.DestinationAddress)
	if !provider.backend.Allowed("udp", source, dest, udpPort, now) {
		t.Fatal("provider denied authorized UDP tuple")
	}
	if provider.backend.Allowed("tcp", source, dest, udpPort, now) {
		t.Fatal("provider admitted TCP against UDP share")
	}
}

// TestAgentE2ES3PermissionPlanesStayIndependent covers HN-502's authorization
// invariant: permission to call the S3 RPC does not imply permission to open
// its TCP share, and network access does not imply permission to mint a new
// presigned URL through RPC.
func TestAgentE2ES3PermissionPlanesStayIndependent(t *testing.T) {
	hub, err := NewTestHub()
	if err != nil {
		t.Fatalf("NewTestHub: %v", err)
	}
	defer hub.Close()

	provider := startAgent(t, hub.Port(), "s3-provider")
	caller := startAgent(t, hub.Port(), "s3-caller")
	provider.waitRegistered(t, "s3-provider")
	caller.waitRegistered(t, "s3-caller")

	const s3Port = 9001
	resourceID := provider.publishShare(t, "s3", "tcp", s3Port)
	caller.agent.SetResourceGeneration(resourceID, 1)
	callerKey := providerKey(t, caller)
	sender := caller.agent.HubService().Sender()
	if sender == nil {
		t.Fatal("caller sender not connected")
	}
	candidates := []protocol.Candidate{{
		Version: protocol.WireVersion, CandidateID: "cand-s3", SessionID: "sess-s3",
		Key: providerKey(t, provider), Kind: "host", Transport: "udp",
		Address: "198.51.100.30", Port: 51820, Priority: 100,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	}}

	hub.SetRPCAccess(callerKey, true)
	hub.SetNetworkAccess(callerKey, false)
	if _, err := channelgo.Send[string](sender, "s3/read", "object"); err != nil {
		t.Fatalf("RPC permission should allow s3/read: %v", err)
	}
	if _, err := caller.agent.ConnectToShare(context.Background(), resourceID, "", candidates); err == nil {
		t.Fatal("RPC permission accidentally granted network access")
	}

	hub.SetRPCAccess(callerKey, false)
	hub.SetNetworkAccess(callerKey, true)
	if _, err := channelgo.Send[string](sender, "s3/read", "object"); err == nil {
		t.Fatal("network permission accidentally granted RPC access")
	}
	if _, err := caller.agent.ConnectToShare(context.Background(), resourceID, "", candidates); err != nil {
		t.Fatalf("network permission should allow S3 share: %v", err)
	}
}

// TestAgentE2EBlockedPortRejectsTamperedGrant proves the no-relay fail-closed
// behavior through the agent: a grant whose DestinationPort has been mutated
// after signing fails signature verification inside ConnectToShare before any
// candidate is consulted, and installs no peer.
func TestAgentE2EBlockedPortRejectsTamperedGrant(t *testing.T) {
	hub, err := NewTestHub()
	if err != nil {
		t.Fatalf("NewTestHub: %v", err)
	}
	defer hub.Close()

	provider := startAgent(t, hub.Port(), "provider")
	caller := startAgent(t, hub.Port(), "caller")
	provider.waitRegistered(t, "provider")
	caller.waitRegistered(t, "caller")

	const (
		shareName            = "factorio"
		publishedPort uint16 = 34197
		blockedPort   uint16 = 25565
	)
	resourceID := provider.publishShare(t, shareName, "tcp", publishedPort)
	caller.agent.SetResourceGeneration(resourceID, 1)

	candidates := []protocol.Candidate{{
		Version: protocol.WireVersion, CandidateID: "cand-blocked", SessionID: "sess-blocked",
		Key: providerKey(t, provider), Kind: "host", Transport: "udp",
		Address: "198.51.100.30", Port: 51820, Priority: 100,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	}}
	grant, err := caller.agent.ConnectToShare(context.Background(), resourceID, "", candidates)
	if err != nil {
		t.Fatalf("ConnectToShare published: %v", err)
	}
	if err := provider.agent.AuthorizeFlow(grant); err != nil {
		t.Fatalf("AuthorizeFlow published: %v", err)
	}

	// Tamper the port and leave the stale signature. The verifier must reject
	// before candidate checks. We use a fresh GrantID so the verifier's
	// consumed-grant replay cache (keyed by the original GrantID) does not
	// short-circuit the signature check.
	tampered := grant
	tampered.GrantID = "grant-tampered"
	tampered.DestinationPort = blockedPort
	tampered.Signature = grant.Signature // stale on purpose
	if err := caller.agent.Connections().Connect(context.Background(), tampered, candidates); err == nil {
		t.Fatal("tampered grant was accepted")
	}

	// Firewall still admits only the published port.
	now := time.Now()
	source, _ := netip.ParseAddr(grant.CallerAddress)
	dest, _ := netip.ParseAddr(grant.DestinationAddress)
	if provider.backend.Allowed("tcp", source, dest, blockedPort, now) {
		t.Fatal("provider admitted blocked port")
	}
	if !provider.backend.Allowed("tcp", source, dest, publishedPort, now) {
		t.Fatal("provider denied published port after tamper attempt")
	}
}

// TestAgentE2ERevocationTerminatesFlow proves that after the Hub revokes a
// resource (generation bump), the provider's enforcement manager removes the
// authorization rule and the immediate-revocation path asks the backend to
// terminate matching flows.
func TestAgentE2ERevocationTerminatesFlow(t *testing.T) {
	hub, err := NewTestHub()
	if err != nil {
		t.Fatalf("NewTestHub: %v", err)
	}
	defer hub.Close()

	provider := startAgent(t, hub.Port(), "provider")
	caller := startAgent(t, hub.Port(), "caller")
	provider.waitRegistered(t, "provider")
	caller.waitRegistered(t, "caller")

	const (
		shareName = "session"
		tcpPort   = 5000
	)
	resourceID := provider.publishShare(t, shareName, "tcp", tcpPort)
	caller.agent.SetResourceGeneration(resourceID, 1)
	provider.agent.SetResourceGeneration(resourceID, 1)

	candidates := []protocol.Candidate{{
		Version: protocol.WireVersion, CandidateID: "cand-rev", SessionID: "sess-rev",
		Key: providerKey(t, provider), Kind: "host", Transport: "udp",
		Address: "198.51.100.30", Port: 51820, Priority: 100,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	}}
	grant, err := caller.agent.ConnectToShare(context.Background(), resourceID, "", candidates)
	if err != nil {
		t.Fatalf("ConnectToShare: %v", err)
	}
	if err := provider.agent.AuthorizeFlow(grant); err != nil {
		t.Fatalf("AuthorizeFlow: %v", err)
	}

	now := time.Now()
	source, _ := netip.ParseAddr(grant.CallerAddress)
	dest, _ := netip.ParseAddr(grant.DestinationAddress)
	if !provider.backend.Allowed("tcp", source, dest, tcpPort, now) {
		t.Fatal("provider denied authorized tuple before revocation")
	}

	// Hub revokes: generation bumps to 2. The provider updates its trusted
	// generation and immediately terminates matching flows.
	newGen := hub.Revoke(resourceID)
	provider.agent.SetResourceGeneration(resourceID, newGen)
	if err := provider.agent.Enforcement().UpdateGeneration(resourceID, newGen, true); err != nil {
		t.Fatalf("UpdateGeneration: %v", err)
	}

	if provider.backend.Allowed("tcp", source, dest, tcpPort, now) {
		t.Fatal("provider admitted tuple after immediate revocation")
	}
	terminated := provider.backend.Terminated()
	found := false
	for _, rid := range terminated {
		if rid == resourceID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("backend did not terminate flows for %s; terminated=%v", resourceID, terminated)
	}
}

// TestAgentE2EHubReconnectRecovery covers HN-706's Hub-outage recovery slice.
// A real channel-go listener drops both agent transports, returns on the same
// address, and each production reconnect loop replays agent registration.
// Profile keys and Hub-assigned overlay addresses must remain stable.
func TestAgentE2EHubReconnectRecovery(t *testing.T) {
	hub, err := NewTestHub()
	if err != nil {
		t.Fatalf("NewTestHub: %v", err)
	}
	defer hub.Close()

	provider := startAgent(t, hub.Port(), "reconnect-provider")
	caller := startAgent(t, hub.Port(), "reconnect-caller")
	provider.waitRegistered(t, "reconnect-provider")
	caller.waitRegistered(t, "reconnect-caller")

	providerBefore := provider.agent.Profile().Snapshot()
	callerBefore := caller.agent.Profile().Snapshot()
	providerIdentityKey := providerKey(t, provider)
	callerKey := providerKey(t, caller)
	if hub.RegistrationCount(providerIdentityKey) != 1 || hub.RegistrationCount(callerKey) != 1 {
		t.Fatalf("initial registration counts provider=%d caller=%d, want 1 each",
			hub.RegistrationCount(providerIdentityKey), hub.RegistrationCount(callerKey))
	}

	if err := hub.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hub.RegistrationCount(providerIdentityKey) >= 2 && hub.RegistrationCount(callerKey) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if hub.RegistrationCount(providerIdentityKey) < 2 || hub.RegistrationCount(callerKey) < 2 {
		t.Fatalf("re-registration counts provider=%d caller=%d, want >=2 each",
			hub.RegistrationCount(providerIdentityKey), hub.RegistrationCount(callerKey))
	}

	providerAfter := provider.agent.Profile().Snapshot()
	callerAfter := caller.agent.Profile().Snapshot()
	if providerAfter.Key != providerBefore.Key ||
		providerAfter.OverlayAddress != providerBefore.OverlayAddress {
		t.Fatalf("provider binding changed across reconnect: before=%+v after=%+v",
			providerBefore, providerAfter)
	}
	if callerAfter.Key != callerBefore.Key ||
		callerAfter.OverlayAddress != callerBefore.OverlayAddress {
		t.Fatalf("caller binding changed across reconnect: before=%+v after=%+v",
			callerBefore, callerAfter)
	}
}

// TestAgentE2EProcessRestartRecovery covers HN-706's agent-restart slice.
// Replacement process reads the same persistent identity and WireGuard key,
// re-registers against Hub, and receives the existing stable overlay binding.
func TestAgentE2EProcessRestartRecovery(t *testing.T) {
	hub, err := NewTestHub()
	if err != nil {
		t.Fatalf("NewTestHub: %v", err)
	}
	defer hub.Close()

	stateDir := t.TempDir()
	first := startAgentWithState(t, hub.Port(), "process-restart", stateDir)
	first.waitRegistered(t, "process-restart-first")
	before := first.agent.Profile().Snapshot()
	beforeKey := providerKey(t, first)
	beforeWireGuardKey := first.agent.Profile().WireGuardPublicKey()

	first.stopAgent(t, "process-restart-first")

	replacement := startAgentWithState(t, hub.Port(), "process-restart", stateDir)
	replacement.waitRegistered(t, "process-restart-replacement")
	after := replacement.agent.Profile().Snapshot()
	afterKey := providerKey(t, replacement)
	afterWireGuardKey := replacement.agent.Profile().WireGuardPublicKey()

	if afterKey != beforeKey {
		t.Fatalf("profile identity changed across process restart")
	}
	if !bytes.Equal(afterWireGuardKey, beforeWireGuardKey) {
		t.Fatalf("WireGuard identity changed across process restart")
	}
	if after.Key != before.Key || after.OverlayAddress != before.OverlayAddress {
		t.Fatalf("Hub binding changed across process restart: before=%+v after=%+v",
			before, after)
	}
	if got := hub.RegistrationCount(beforeKey); got != 2 {
		t.Fatalf("registration count after process restart = %d, want 2", got)
	}
}

// TestAgentE2EManualTCPUDPServiceRepublishesAfterHubRestart covers HN-706's
// manual-service, TCP/UDP, and reconnect-recovery slices. A separately
// identified Go service attests through the provider agent's Unix socket,
// atomically publishes both game shares, obtains usable grants, then
// automatically republishes both after the Hub transport restarts.
func TestAgentE2EManualTCPUDPServiceRepublishesAfterHubRestart(t *testing.T) {
	hub, err := NewTestHub()
	if err != nil {
		t.Fatalf("NewTestHub: %v", err)
	}
	defer hub.Close()

	provider := startAgent(t, hub.Port(), "manual-provider")
	caller := startAgent(t, hub.Port(), "manual-caller")
	provider.waitRegistered(t, "manual-provider")
	caller.waitRegistered(t, "manual-caller")

	serviceIdentity, err := identity.Generate()
	if err != nil {
		t.Fatalf("service identity: %v", err)
	}
	serviceKey, err := serviceIdentity.PublicKeyBase64()
	if err != nil {
		t.Fatalf("service public key: %v", err)
	}
	service, err := hubconn.New(hubconn.Options{
		Identity:       serviceIdentity,
		Address:        hub.Port(),
		Name:           "manual-game-server",
		NetworkOptions: servicenetwork.Options{AgentSocket: provider.cfg.AgentSocketPath},
	})
	if err != nil {
		t.Fatalf("new manual service: %v", err)
	}
	publisher := service.Network()
	policy := &servicenetwork.Policy{Mode: servicenetwork.PolicyHub}
	const (
		tcpShare = "manual-game-tcp"
		udpShare = "manual-game-udp"
		tcpPort  = 25565
		udpPort  = 19132
	)
	service.Share(tcpShare, servicenetwork.ProtocolTCP, "127.0.0.1", tcpPort, policy)
	service.Share(udpShare, servicenetwork.ProtocolUDP, "127.0.0.1", udpPort, policy)
	if err := service.Start(); err != nil {
		t.Fatalf("start manual service: %v", err)
	}
	defer service.Stop()

	publications := make(map[string]protocol.NetworkSharePublication)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		tcpPublication, tcpOK := publisher.Publication(tcpShare)
		udpPublication, udpOK := publisher.Publication(udpShare)
		if tcpOK && udpOK {
			publications[tcpShare] = tcpPublication
			publications[udpShare] = udpPublication
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(publications) != 2 {
		t.Fatalf("manual service publications = %d, want 2", len(publications))
	}
	if got := hub.ShareReplaceCount(serviceKey); got != 1 {
		t.Fatalf("initial share replacement count = %d, want 1", got)
	}

	caller.agent.SetResourceGeneration(publications[tcpShare].ResourceID, 1)
	caller.agent.SetResourceGeneration(publications[udpShare].ResourceID, 1)
	provider.agent.SetResourceGeneration(publications[tcpShare].ResourceID, 1)
	provider.agent.SetResourceGeneration(publications[udpShare].ResourceID, 1)
	candidates := []protocol.Candidate{{
		Version: protocol.WireVersion, CandidateID: "cand-manual", SessionID: "sess-manual",
		Key: providerKey(t, provider), Kind: "host", Transport: "udp",
		Address: "198.51.100.30", Port: 51820, Priority: 100,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	}}
	tcpGrant, err := caller.agent.ConnectToShare(
		context.Background(), publications[tcpShare].ResourceID, "", candidates)
	if err != nil {
		t.Fatalf("connect manual TCP share: %v", err)
	}
	udpGrant, err := caller.agent.ConnectToShare(
		context.Background(), publications[udpShare].ResourceID, "", candidates)
	if err != nil {
		t.Fatalf("connect manual UDP share: %v", err)
	}
	if err := provider.agent.AuthorizeFlow(tcpGrant); err != nil {
		t.Fatalf("authorize manual TCP share: %v", err)
	}
	if err := provider.agent.AuthorizeFlow(udpGrant); err != nil {
		t.Fatalf("authorize manual UDP share: %v", err)
	}
	now := time.Now()
	source := netip.MustParseAddr(tcpGrant.CallerAddress)
	destination := netip.MustParseAddr(tcpGrant.DestinationAddress)
	if !provider.backend.Allowed("tcp", source, destination, tcpPort, now) {
		t.Fatal("manual TCP share denied after authorization")
	}
	if !provider.backend.Allowed("udp", source, destination, udpPort, now) {
		t.Fatal("manual UDP share denied after authorization")
	}

	if err := hub.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hub.ShareReplaceCount(serviceKey) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := hub.ShareReplaceCount(serviceKey); got < 2 {
		t.Fatalf("share replacement count after reconnect = %d, want >=2", got)
	}
	for _, shareName := range []string{tcpShare, udpShare} {
		after, ok := publisher.Publication(shareName)
		if !ok {
			t.Fatalf("manual service publication %s missing after reconnect", shareName)
		}
		before := publications[shareName]
		if after.ResourceID != before.ResourceID ||
			after.OverlayAddress != before.OverlayAddress ||
			after.Protocol != before.Protocol ||
			after.Port != before.Port {
			t.Fatalf("%s publication changed across reconnect: before=%+v after=%+v",
				shareName, before, after)
		}
	}
}

// providerKey returns the provider agent's authenticated key (base64 SPKI
// of its Hub identity), used to populate the candidate.Key that the
// connection manager matches against grant.TargetKey.
func providerKey(t *testing.T, s *agentSide) string {
	t.Helper()
	id := s.agent.HubService().Identity()
	pub, err := id.PublicKeyBase64()
	if err != nil {
		t.Fatalf("provider agent key: %v", err)
	}
	return pub
}

// agentSelfAttestation performs the IPC attestation flow against the agent's
// own Unix socket using its own Hub identity as the service identity. Mirrors
// the hubconn/network Publisher wire path.
func agentSelfAttestation(t *testing.T, socketPath string, id *identity.Identity, shareName, proto, host string, port uint16) protocol.AgentAttestation {
	t.Helper()
	serviceKey, err := id.PublicKeyBase64()
	if err != nil {
		t.Fatalf("service key: %v", err)
	}
	challengeBody := map[string]any{
		"serviceKey": serviceKey, "shareName": shareName, "protocol": proto,
		"target": map[string]any{"host": host, "port": port},
	}
	challenge, status, err := postJSONAgent(socketPath, "/challenge", challengeBody)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("challenge status = %d body = %v", status, challenge)
	}
	nonce, _ := challenge["nonce"].(string)
	if nonce == "" {
		t.Fatalf("challenge returned empty nonce")
	}
	signature := id.Sign([]byte(nonce))
	attestBody := map[string]any{
		"serviceKey": serviceKey, "shareName": shareName, "protocol": proto,
		"target": map[string]any{"host": host, "port": port}, "signature": signature,
	}
	resp, status, err := postJSONAgent(socketPath, "/attest", attestBody)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("attest status = %d body = %v", status, resp)
	}
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal attestation: %v", err)
	}
	var att protocol.AgentAttestation
	if err := json.Unmarshal(encoded, &att); err != nil {
		t.Fatalf("decode attestation: %v", err)
	}
	return att
}

func postJSONAgent(socketPath, path string, body any) (map[string]any, int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://localhost"+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("content-type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)
	var decoded map[string]any
	_ = json.Unmarshal(payload, &decoded)
	return decoded, response.StatusCode, nil
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", path)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("socket %s not ready", path)
}

// alwaysOKCandidateAgent mirrors e2e.alwaysOKCandidate but lives in the
// agent-level package so it satisfies hubnet.Options.CandidateChecker.
type alwaysOKCandidateAgent struct{}

func (alwaysOKCandidateAgent) Check(context.Context, protocol.Candidate) error { return nil }

// alwaysOKHandshakeAgent mirrors e2e.alwaysOKHandshake.
type alwaysOKHandshakeAgent struct{}

func (alwaysOKHandshakeAgent) Wait(context.Context, []byte) error { return nil }
