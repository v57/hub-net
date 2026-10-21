// Package e2e contains the Hub Network local end-to-end test harness.
//
// HN-310 proves the agent's core data-plane authorization chain against two
// isolated in-process agents. The harness wires together the real components
// without a Hub control plane:
//
//   - Two agent sides (caller and provider) each own an Ed25519 Hub identity,
//     a Curve25519 WireGuard key, a separate overlay address, a
//     wireguard.FakeAdapter, an enforcement.Manager backed by
//     enforcement.MemoryBackend, and an ipc.Server bound to a real Unix socket.
//   - A shared in-memory Hub signing identity mints the cross-language
//     ConnectionGrant envelope (protocol.PurposeConnectionGrant) the same way
//     hub-server does.
//
// The harness exercises every authorization stage the agent ships: the local
// IPC attestation flow that proves a service owns a local target, the
// ConnectionGrant verifier that binds caller, target, port, and overlay
// address, the WireGuard adapter that installs only the authorized peer key
// and destination /32, and the per-resource enforcement manager that installs
// the exact signed (source, destination, protocol, port) tuple.
//
// No relay path exists. The harness confirms direct-establishment behavior
// (grants authorize the WireGuard peer + firewall tuple) and that a blocked
// port is rejected by every layer. Real socket/handshake establishment stays
// out of scope — HN-311 wires the platform pieces — so the harness uses the
// FakeAdapter and a deterministic handshake checker.
package e2e

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/v57/hub-net-node/identity"
	protocol "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net/connection"
	"github.com/v57/hub-net/enforcement"
	"github.com/v57/hub-net/grant"
	"github.com/v57/hub-net/ipc"
	"github.com/v57/hub-net/wireguard"
)

// ErrDirectFailed mirrors connection.ErrDirectFailed so tests can assert the
// no-relay direct-establishment failure without importing the connection
// package directly. The harness guarantees the two sides never gain
// unauthorized access through a fallback path.
var ErrDirectFailed = connection.ErrDirectFailed

// HubNetworkID is the fixed overlay network identifier both sides belong to.
// hub-server allocates this per Hub; the harness treats it as trusted state.
const HubNetworkID = "hnet-e2e"

// ResourceGeneration is the current authorization generation for the single
// shared resource the harness publishes. The verifier consults the lookup and
// fails closed when a grant claims a stale generation.
const ResourceGeneration uint64 = 1

// HandshakeTimeout bounds the WireGuard handshake wait. Always-OK handshake
// checker returns immediately; the value just bounds the negative test path.
const HandshakeTimeout = 2 * time.Second

// IdleTimeout bounds how long an installed peer stays alive without use.
const IdleTimeout = 5 * time.Minute

// Side is one isolated in-process agent (caller or provider). Every field is
// real agent code wired against deterministic test doubles.
type Side struct {
	Name            string
	Identity        *identity.Identity
	ServiceKey      string
	WireGuardPriv   []byte
	WireGuardPubB64 string
	OverlayAddress  string
	Key             string

	Adapter    *wireguard.FakeAdapter
	Enforce    *enforcement.Manager
	Backend    *enforcement.MemoryBackend
	Verifier   *grant.Verifier
	Connection *connection.Manager

	ipcServer *ipc.Server
	ipcErrs   <-chan error
	socket    string
}

// Harness is the two-agent local end-to-end fixture.
type Harness struct {
	t        *testing.T
	caller   *Side
	provider *Side
	hubKey   string
	hubPriv  ed25519.PrivateKey
}

// New builds the two-side harness: caller + provider, isolated identities and
// overlay addresses, real Unix-socket IPC servers, real adapters, real
// enforcement managers. Each piece is cleaned up on test completion.
func New(t *testing.T) *Harness {
	t.Helper()
	hubPublic, hubPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("hub key: %v", err)
	}
	hubDER, err := x509.MarshalPKIXPublicKey(hubPublic)
	if err != nil {
		t.Fatalf("marshal hub key: %v", err)
	}
	h := &Harness{
		t:        t,
		hubKey:   base64.StdEncoding.EncodeToString(hubDER),
		hubPriv:  hubPrivate,
		caller:   newSide(t, "caller", "100.96.0.10"),
		provider: newSide(t, "provider", "100.96.0.20"),
	}
	// Both sides trust the same Hub signing key.
	h.caller.bindVerifier(h.hubKey)
	h.provider.bindVerifier(h.hubKey)
	return h
}

// Caller returns the caller-side agent.
func (h *Harness) Caller() *Side { return h.caller }

// Provider returns the provider-side agent.
func (h *Harness) Provider() *Side { return h.provider }

// HubKey returns the trusted Hub signing public key, base64 SPKI. This is the
// value both grant verifiers and the production agent use to validate grant
// signatures.
func (h *Harness) HubKey() string { return h.hubKey }

// IssueGrant mints a Hub-signed ConnectionGrant authorizing Caller to reach
// the published share on Provider. It mirrors what hub-server issues after
// profile registration, attestation validation, and policy evaluation.
//
// Destination port is the published overlay port. The provider overlay
// address is the destination; the caller overlay address is the source. The
// grant is signed in the connection-grant domain so it cannot replay as an
// attestation or ticket.
func (h *Harness) IssueGrant(resourceID, protocolName string, port uint16) protocol.ConnectionGrant {
	now := time.Now().UTC()
	g := protocol.ConnectionGrant{
		Version:            protocol.WireVersion,
		GrantID:            "grant-" + resourceID + "-" + protocolName,
		HubKey:             h.hubKey,
		HubNetworkID:       HubNetworkID,
		CallerKey:          h.caller.Key,
		CallerWireGuardKey: h.caller.WireGuardPubB64,
		CallerAddress:      h.caller.OverlayAddress,
		TargetKey:          h.provider.Key,
		TargetWireGuardKey: h.provider.WireGuardPubB64,
		ResourceID:         resourceID,
		ProviderID:         "provider-" + resourceID,
		Protocol:           protocolName,
		DestinationAddress: h.provider.OverlayAddress,
		DestinationPort:    port,
		Generation:         ResourceGeneration,
		IssuedAt:           now.Format(time.RFC3339Nano),
		ExpiresAt:          now.Add(protocol.ConnectionGrantMaxLifetime - time.Second).Format(time.RFC3339Nano),
	}
	signature, err := protocol.SignEnvelope(protocol.PurposeConnectionGrant, g, h.hubPriv)
	if err != nil {
		h.t.Fatalf("sign grant: %v", err)
	}
	g.Signature = signature
	return g
}

// Candidates returns a single direct UDP candidate for the provider's
// transport endpoint. Production hubs exchange candidates via the rendezvous
// node; the harness supplies one because candidate delivery is transport
// metadata only and never authorization.
func (h *Harness) Candidates(now time.Time) []protocol.Candidate {
	return []protocol.Candidate{{
		Version: protocol.WireVersion, CandidateID: "cand-direct",
		SessionID: "session-e2e", Key: h.provider.Key,
		Kind: "host", Transport: "udp", Address: "198.51.100.20", Port: 51820,
		Priority: 100, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}}
}

// newSide constructs a fully wired agent side: identity, WireGuard key,
// overlay address, FakeAdapter, enforcement manager, and a real Unix-socket
// IPC server. The hub public key is also threaded into the grant verifier so
// every side trusts the same authority.
func newSide(t *testing.T, name, overlayAddress string) *Side {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("%s identity: %v", name, err)
	}
	serviceKey, err := id.PublicKeyBase64()
	if err != nil {
		t.Fatalf("%s service key: %v", name, err)
	}
	wgPriv := make([]byte, 32)
	if _, err := rand.Read(wgPriv); err != nil {
		t.Fatalf("%s wireguard key: %v", name, err)
	}
	wgPub := deriveWireGuardPublic(wgPriv, t, name)
	wgPubB64 := base64.StdEncoding.EncodeToString(wgPub)

	adapter := wireguard.NewFakeAdapter()
	overlayAddr := netip.MustParseAddr(overlayAddress)
	if err := adapter.Up(wireguard.InterfaceConfig{
		Name: "hubnet-" + name, PrivateKey: wgPriv,
		Address: overlayAddr, ListenPort: 51820,
	}); err != nil {
		t.Fatalf("%s adapter Up: %v", name, err)
	}

	backend := &enforcement.MemoryBackend{}
	manager, err := enforcement.New(backend)
	if err != nil {
		t.Fatalf("%s enforcement manager: %v", name, err)
	}

	socketPath := shortSocketPath(t, name)
	handler, err := ipc.NewAttestHandler(ipc.AttestHandlerOptions{
		Agent:          id,
		Policy:         ipc.DefaultTargetPolicy(),
		AttestationTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("%s attest handler: %v", name, err)
	}
	server, err := ipc.NewServer(ipc.ServerOptions{
		SocketPath: socketPath,
		Handler:    handler,
		// Test clients connect from arbitrary goroutines; relax peer-credential
		// enforcement. Production agents require a verified local uid.
		PeerPolicy: ipc.PeerPolicy{AllowAnyLocal: true},
	})
	if err != nil {
		t.Fatalf("%s ipc server: %v", name, err)
	}
	ipcErrs := server.Start(context.Background())
	t.Cleanup(func() {
		_ = server.Close(context.Background())
		<-ipcErrs
		_ = os.Remove(socketPath)
	})

	return &Side{
		Name: name, Identity: id, ServiceKey: serviceKey,
		WireGuardPriv: wgPriv, WireGuardPubB64: wgPubB64,
		OverlayAddress: overlayAddress, Key: serviceKey,
		Adapter: adapter, Enforce: manager, Backend: backend,
		ipcServer: server, ipcErrs: ipcErrs, socket: socketPath,
	}
}

// bindVerifier wires the connection-grant verifier against the side's trusted
// local binding (own identity + the trusted Hub key). Authorization of the
// counterparty happens through the signed grant, not through trust.
func (s *Side) bindVerifier(hubKey string) {
	var bindErr error
	s.Verifier, bindErr = grant.NewVerifier(grant.LocalBinding{
		HubKey: hubKey, HubNetworkID: HubNetworkID,
		CallerKey: s.Key, CallerWireGuardKey: s.WireGuardPubB64,
	}, func(resourceID string) (uint64, bool) {
		if resourceID == "" {
			return 0, false
		}
		return ResourceGeneration, true
	})
	if bindErr != nil {
		panic(fmt.Sprintf("%s verifier: %v", s.Name, bindErr))
	}
	s.Connection = mustConnectionManager(s)
}

// mustConnectionManager builds the connection.Manager for the side, backed by
// the side's verifier, FakeAdapter, a deterministic always-OK handshake
// checker, and a candidate checker that accepts the harness's single
// candidate. Production paths plug in real handshake observation; the
// deterministic checker is what makes the e2e harness hermetic.
func mustConnectionManager(s *Side) *connection.Manager {
	m, err := connection.New(connection.Options{
		Adapter: s.Adapter, Verifier: s.Verifier,
		CandidateChecker: &alwaysOKCandidate{},
		HandshakeChecker: &alwaysOKHandshake{},
		HandshakeTimeout: HandshakeTimeout, IdleTimeout: IdleTimeout,
	})
	if err != nil {
		panic(fmt.Sprintf("%s connection manager: %v", s.Name, err))
	}
	return m
}

// SocketPath returns the real Unix socket path the side's IPC server listens
// on. The hubconn/network Publisher reaches the agent through this path.
func (s *Side) SocketPath() string { return s.socket }

// Allowed reports whether the enforcement backend would admit the signed
// (source, destination, protocol, port) tuple at the given time. The harness
// uses it as the firewall verdict — production backends translate the rule
// into nftables or the equivalent platform firewall.
func (s *Side) Allowed(protocolName string, source, destination netip.Addr, port uint16, now time.Time) bool {
	return s.Backend.Allowed(protocolName, source, destination, port, now)
}

// alwaysOKCandidate accepts every candidate the harness supplies. Candidate
// delivery is transport metadata; the verifier decides authorization.
type alwaysOKCandidate struct{}

func (*alwaysOKCandidate) Check(context.Context, protocol.Candidate) error { return nil }

// alwaysOKHandshake reports a successful WireGuard handshake for every key.
// Production agents wait for a real handshake observation; the deterministic
// checker is what makes the e2e harness hermetic.
type alwaysOKHandshake struct{}

func (*alwaysOKHandshake) Wait(context.Context, []byte) error { return nil }

// deriveWireGuardPublic mirrors hubnet.wireGuardPublicKey so the harness does
// not depend on the internal package. WireGuard uses Curve25519 scalar
// multiplication, the same primitive crypto/ecdh exposes.
func deriveWireGuardPublic(privateKey []byte, t *testing.T, name string) []byte {
	t.Helper()
	curve := ecdh.X25519()
	key, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("%s derive wireguard public: %v", name, err)
	}
	return key.PublicKey().Bytes()
}

// shortSocketPath returns a short Unix socket path under the system temp dir.
// macOS caps Unix socket paths near 104 bytes, so we keep the path small
// rather than embedding a long test name.
func shortSocketPath(t *testing.T, name string) string {
	t.Helper()
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("socket rand: %v", err)
	}
	return filepath.Join(os.TempDir(), "hn-e2e-"+name+"-"+hex.EncodeToString(buf[:])+".sock")
}
