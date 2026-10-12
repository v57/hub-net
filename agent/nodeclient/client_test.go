package nodeclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/v57/hub-net-node/config"
	"github.com/v57/hub-net-node/protocol"
	"github.com/v57/hub-net-node/server"
	"github.com/v57/hub-service-go/identity"
	network "github.com/v57/hub-service-go/protocol"
)

// runNodeServer boots a real hub-net-node rendezvous server on a random
// loopback port.
func runNodeServer(t *testing.T) (string, func()) {
	t.Helper()
	cfg := config.Defaults()
	cfg.StateDir = t.TempDir() + "/node-state"
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.NodeID = "nodeclient-test"
	if err := cfg.Resolve(); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	srv, err := server.New(server.Options{
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()
	address := ""
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

// signedInvitation builds a compact invitation signed by id and returns the
// code plus its SHA-256(payload) replay digest.
func signedInvitation(t *testing.T, id *identity.Identity) (code, digest string) {
	t.Helper()
	var nonce, expires [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(expires[:], uint32(time.Now().Add(7*24*time.Hour).Unix()))
	payload := base64.RawURLEncoding.EncodeToString(id.PublicKey()) + "." +
		base64.RawURLEncoding.EncodeToString(expires[:]) + "." +
		base64.RawURLEncoding.EncodeToString(nonce[:])
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(id.PrivateKey(), []byte(payload)))
	sum := sha256.Sum256([]byte(payload))
	return payload + "/" + signature, base64.RawURLEncoding.EncodeToString(sum[:])
}

func serviceKey(t *testing.T, id *identity.Identity) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(id.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func waitOnline(t *testing.T, client *Client) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if client.Online() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("client never reported online")
}

func waitOffline(t *testing.T, client *Client, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client Run did not stop")
	}
	if client.Online() {
		t.Fatal("client still online after cancellation")
	}
}

func sendInvitationUDPProbe(t *testing.T, address string, probe protocol.InvitationUDPProbe) {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	response := make([]byte, 1024)
	if _, err := conn.Read(response); err != nil {
		t.Fatalf("invitation UDP probe response: %v", err)
	}
}

func openInvitationSession(t *testing.T, address, code, digest, key string) protocol.Envelope {
	t.Helper()
	sendInvitationUDPProbe(t, address, protocol.InvitationUDPProbe{
		Version: 1, InvitationCode: code, Key: key,
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstanceID: "tunnel-live", Generation: 7,
	})
	conn, err := DialWebSocket(context.Background(), address)
	if err != nil {
		t.Fatalf("dial joiner websocket: %v", err)
	}
	defer conn.Close()
	if err := WriteEnvelope(conn, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: key,
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstance: "tunnel-live", Generation: 7,
	}); err != nil {
		t.Fatalf("open session: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := ReadEnvelope(conn)
	if err != nil {
		t.Fatalf("read join reply: %v", err)
	}
	return reply
}

// TestClientRegistrationEnablesAndDisablesJoins proves the client's signed
// challenge handshake registers the agent with the real node (a join carrying
// its invitation is accepted), and that cancellation drops the registration
// (the same invitation is then rejected with inviter offline).
func TestClientRegistrationEnablesAndDisablesJoins(t *testing.T) {
	address, cleanup := runNodeServer(t)
	defer cleanup()

	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	code, digest := signedInvitation(t, id)
	key := serviceKey(t, id)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := New(Options{
		Endpoint: func() string { return address },
		Identity: id,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	waitOnline(t, client)

	reply := openInvitationSession(t, address, code, digest, key)
	if reply.Type != protocol.MessageSessionOpened || reply.SessionID == "" {
		t.Fatalf("online join = %+v, want session.opened", reply)
	}

	cancel()
	waitOffline(t, client, done)

	// A fresh probe and a distinct joiner key avoid the consumed replay entry;
	// the rejection must come from the offline inviter, not replay state.
	rejected := openInvitationSession(t, address, code, digest, "joiner-after-offline")
	if rejected.Type != protocol.MessageError || rejected.Error == nil ||
		rejected.Error.Code != "unauthorized" || rejected.Error.Retryable {
		t.Fatalf("offline join = %+v, want non-retryable unauthorized", rejected)
	}
}

// TestClientEndpointFallback verifies the client retries when no endpoint is
// configured and connects once one appears.
func TestClientEndpointFallback(t *testing.T) {
	address, cleanup := runNodeServer(t)
	defer cleanup()

	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var endpoint atomic.Value
	endpoint.Store("")
	client, err := New(Options{
		Endpoint: func() string {
			value, _ := endpoint.Load().(string)
			return value
		},
		Identity: id,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	if client.Online() {
		t.Fatal("client online before endpoint configured")
	}
	endpoint.Store(address)
	waitOnline(t, client)
	cancel()
	waitOffline(t, client, done)
}

// TestClientParticipatesInInvitationBootstrapSession proves the node signals
// the registered inviter when a joiner opens a session with one of its
// invitations, and that the client probes, opens its side of the paired
// session on the registration connection, offers the inviter's candidate, and
// reports the joiner's candidates to the Bootstrap handler.
func TestClientParticipatesInInvitationBootstrapSession(t *testing.T) {
	address, cleanup := runNodeServer(t)
	defer cleanup()

	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	code, digest := signedInvitation(t, id)
	inviterKey := serviceKey(t, id)

	events := make(chan BootstrapEvent, 4)
	client, err := New(Options{
		Endpoint:  func() string { return address },
		Identity:  id,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Bootstrap: func(event BootstrapEvent) { events <- event },
		Candidates: func() []network.Candidate {
			return []network.Candidate{{
				CandidateID: "inviter-host", Kind: "host",
				Address: "192.0.2.44", Port: 51820, Priority: 100,
			}}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	waitOnline(t, client)

	// Joiner probes and opens its side first (client-initiated flow).
	joinerKey := "joiner-service-key"
	sendInvitationUDPProbe(t, address, protocol.InvitationUDPProbe{
		Version: 1, InvitationCode: code, Key: joinerKey,
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstanceID: "tunnel-live", Generation: 7,
	})
	joiner, err := DialWebSocket(context.Background(), address)
	if err != nil {
		t.Fatalf("dial joiner websocket: %v", err)
	}
	defer joiner.Close()
	if err := WriteEnvelope(joiner, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: joinerKey,
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstance: "tunnel-live", Generation: 7,
	}); err != nil {
		t.Fatalf("joiner open session: %v", err)
	}
	_ = joiner.SetReadDeadline(time.Now().Add(3 * time.Second))
	joinerOpened, err := ReadEnvelope(joiner)
	if err != nil {
		t.Fatalf("read joiner session.opened: %v", err)
	}
	if joinerOpened.Type != protocol.MessageSessionOpened || joinerOpened.SessionID == "" {
		t.Fatalf("joiner open = %+v", joinerOpened)
	}

	// Joiner offers its direct candidate.
	candidate := network.Candidate{
		Version: 1, CandidateID: "joiner-host", SessionID: joinerOpened.SessionID,
		Key: joinerKey, Kind: "host", Transport: "udp",
		Address: "192.0.2.99", Port: 51820, Priority: 100,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	}
	if err := WriteEnvelope(joiner, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOfferCandidate,
		SessionID: joinerOpened.SessionID, Candidate: &candidate,
	}); err != nil {
		t.Fatalf("joiner offer candidate: %v", err)
	}

	// The registered client must open its side and report the joiner's
	// candidates and observed endpoint to the Bootstrap handler.
	select {
	case event := <-events:
		if event.JoinerKey != joinerKey || event.TransactionID != "transaction" ||
			event.TunnelInstanceID != "tunnel-live" || event.Generation != 7 {
			t.Fatalf("bootstrap event identity = %+v", event)
		}
		if len(event.Candidates) != 1 || event.Candidates[0].Address != "192.0.2.99" ||
			event.Candidates[0].Key != joinerKey {
			t.Fatalf("bootstrap event candidates = %+v", event.Candidates)
		}
		if event.Observed.Key != joinerKey || event.Observed.Address == "" || event.Observed.Port == 0 {
			t.Fatalf("bootstrap event observed = %+v", event.Observed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client never received joiner bootstrap event")
	}

	// The joiner must receive the inviter's offered candidate and its
	// node-observed endpoint.
	_ = joiner.SetReadDeadline(time.Now().Add(3 * time.Second))
	seen := false
	for i := 0; i < 5 && !seen; i++ {
		reply, err := ReadEnvelope(joiner)
		if err != nil {
			break
		}
		if reply.Type != protocol.MessageCandidates {
			continue
		}
		if reply.Observed == nil || reply.Observed.Key != inviterKey {
			continue
		}
		for _, delivered := range reply.Candidates {
			if delivered.CandidateID == "inviter-host" && delivered.Address == "192.0.2.44" &&
				delivered.Port == 51820 && delivered.Key == inviterKey {
				seen = true
				break
			}
		}
	}
	if !seen {
		t.Fatal("joiner never received inviter candidate and observed endpoint")
	}

	cancel()
	waitOffline(t, client, done)
}

// TestClientSecondBootstrapExchangeOnSameRegistration proves a registered
// inviter can serve two distinct joiners over one registration connection: the
// client must release its paired bootstrap session after the first exchange
// (MessageCloseSession) so the node does not reject the second session.open
// with "session already open". Regression for the Linux acceptance run.
func TestClientSecondBootstrapExchangeOnSameRegistration(t *testing.T) {
	address, cleanup := runNodeServer(t)
	defer cleanup()

	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}

	events := make(chan BootstrapEvent, 8)
	client, err := New(Options{
		Endpoint: func() string { return address },
		Identity: id,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Bootstrap: func(event BootstrapEvent) {
			events <- event
		},
		Candidates: func() []network.Candidate {
			return []network.Candidate{{
				CandidateID: "inviter-host", Kind: "host",
				Address: "192.0.2.44", Port: 51820, Priority: 100,
			}}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	waitOnline(t, client)

	for join := 0; join < 2; join++ {
		// Each join uses a fresh single-use invitation so the node's global
		// replay slot for the first digest does not reject the second joiner.
		code, digest := signedInvitation(t, id)
		joinerKey := fmt.Sprintf("joiner-key-%d", join)
		sendInvitationUDPProbe(t, address, protocol.InvitationUDPProbe{
			Version: 1, InvitationCode: code, Key: joinerKey,
			TokenDigest: digest, TransactionID: fmt.Sprintf("transaction-%d", join),
			TunnelInstanceID: "tunnel-live", Generation: uint64(join),
		})
		joiner, err := DialWebSocket(context.Background(), address)
		if err != nil {
			t.Fatalf("join %d dial joiner websocket: %v", join, err)
		}
		if err := WriteEnvelope(joiner, protocol.Envelope{
			MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
			InvitationCode: code, Key: joinerKey,
			TokenDigest: digest, TransactionID: fmt.Sprintf("transaction-%d", join),
			TunnelInstance: "tunnel-live", Generation: uint64(join),
		}); err != nil {
			t.Fatalf("join %d joiner open session: %v", join, err)
		}
		_ = joiner.SetReadDeadline(time.Now().Add(3 * time.Second))
		opened, err := ReadEnvelope(joiner)
		if err != nil {
			t.Fatalf("join %d read joiner session.opened: %v", join, err)
		}
		if opened.Type != protocol.MessageSessionOpened || opened.SessionID == "" {
			if opened.Type == protocol.MessageError && opened.Error != nil {
				t.Fatalf("join %d joiner open error = %s %s", join, opened.Error.Code, opened.Error.Message)
			}
			t.Fatalf("join %d joiner open = %+v", join, opened)
		}
		if err := WriteEnvelope(joiner, protocol.Envelope{
			MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOfferCandidate,
			SessionID: opened.SessionID,
			Candidate: &network.Candidate{
				Version: 1, CandidateID: "joiner-host", SessionID: opened.SessionID,
				Key: joinerKey, Kind: "host", Transport: "udp",
				Address: fmt.Sprintf("192.0.2.%d", 100+join), Port: 51820, Priority: 100,
				ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
			},
		}); err != nil {
			t.Fatalf("join %d joiner offer candidate: %v", join, err)
		}

		// The client must open its side, report the joiner's candidates, and
		// then release the session so join 1 succeeds on the same connection.
		select {
		case event := <-events:
			if event.JoinerKey != joinerKey {
				t.Fatalf("join %d bootstrap event joiner = %q", join, event.JoinerKey)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("join %d client never received bootstrap event", join)
		}

		// Give the close a moment to reach the node before the next exchange.
		time.Sleep(200 * time.Millisecond)
		joiner.Close()
	}

	cancel()
	waitOffline(t, client, done)
}

// client builds the invitation probe and hands it to the hook instead of
// dialing its own ephemeral UDP socket. The rest of the bootstrap exchange
// (open, offer, receive joiner candidates) proceeds normally.
func TestClientProbeHookDelegates(t *testing.T) {
	address, cleanup := runNodeServer(t)
	defer cleanup()

	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	code, digest := signedInvitation(t, id)
	joinerKey := "joiner-service-key"

	var probeMu sync.Mutex
	var hookProbe protocol.InvitationUDPProbe
	events := make(chan BootstrapEvent, 4)
	client, err := New(Options{
		Endpoint:  func() string { return address },
		Identity:  id,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Bootstrap: func(event BootstrapEvent) { events <- event },
		Probe: func(ctx context.Context, nodeEndpoint string, probe protocol.InvitationUDPProbe, expectedTicketID string) error {
			probeMu.Lock()
			hookProbe = probe
			probeMu.Unlock()
			if expectedTicketID != digest+":"+serviceKey(t, id) {
				t.Errorf("expected ticket id = %q, want %q", expectedTicketID, digest+":"+serviceKey(t, id))
			}
			sendInvitationUDPProbe(t, nodeEndpoint, probe)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	waitOnline(t, client)

	// Joiner probes and opens first; the registered client must use the hook.
	sendInvitationUDPProbe(t, address, protocol.InvitationUDPProbe{
		Version: 1, InvitationCode: code, Key: joinerKey,
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstanceID: "tunnel-hook", Generation: 9,
	})
	joiner, err := DialWebSocket(context.Background(), address)
	if err != nil {
		t.Fatalf("dial joiner websocket: %v", err)
	}
	defer joiner.Close()
	if err := WriteEnvelope(joiner, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOpenSession,
		InvitationCode: code, Key: joinerKey,
		TokenDigest: digest, TransactionID: "transaction",
		TunnelInstance: "tunnel-hook", Generation: 9,
	}); err != nil {
		t.Fatalf("joiner open session: %v", err)
	}
	_ = joiner.SetReadDeadline(time.Now().Add(3 * time.Second))
	opened, err := ReadEnvelope(joiner)
	if err != nil || opened.Type != protocol.MessageSessionOpened || opened.SessionID == "" {
		t.Fatalf("joiner open = %+v, err = %v", opened, err)
	}
	candidate := network.Candidate{
		Version: 1, CandidateID: "joiner-host", SessionID: opened.SessionID,
		Key: joinerKey, Kind: "host", Transport: "udp",
		Address: "192.0.2.99", Port: 51820, Priority: 100,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339Nano),
	}
	if err := WriteEnvelope(joiner, protocol.Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: protocol.MessageOfferCandidate,
		SessionID: opened.SessionID, Candidate: &candidate,
	}); err != nil {
		t.Fatalf("joiner offer candidate: %v", err)
	}

	select {
	case event := <-events:
		if event.TransactionID != "transaction" || event.JoinerKey != joinerKey ||
			event.TunnelInstanceID != "tunnel-hook" || event.Generation != 9 {
			t.Fatalf("bootstrap event identity = %+v", event)
		}
		if len(event.Candidates) != 1 || event.Candidates[0].Address != "192.0.2.99" {
			t.Fatalf("bootstrap event candidates = %+v", event.Candidates)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client never received joiner bootstrap event")
	}

	probeMu.Lock()
	defer probeMu.Unlock()
	if hookProbe.Version != network.WireVersion ||
		hookProbe.InvitationCode != code ||
		hookProbe.Key != serviceKey(t, id) ||
		hookProbe.TokenDigest != digest ||
		hookProbe.TransactionID != "transaction" ||
		hookProbe.TunnelInstanceID != "tunnel-hook" ||
		hookProbe.Generation != 9 {
		t.Fatalf("hook probe = %+v, want full envelope mirror", hookProbe)
	}

	cancel()
	waitOffline(t, client, done)
}

func TestNormalizeEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"127.0.0.1:1964", "ws://127.0.0.1:1964/rendezvous"},
		{"hub.v57.dev/node", "ws://hub.v57.dev/node"},
		{"wss://node.example/rendezvous", "wss://node.example/rendezvous"},
	}
	for _, tc := range cases {
		got, err := normalizeEndpoint(tc.in)
		if err != nil {
			t.Fatalf("normalizeEndpoint(%q): %v", tc.in, err)
		}
		if got.String() != tc.want {
			t.Errorf("normalizeEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "http://example.com", "not a url"} {
		if _, err := normalizeEndpoint(bad); err == nil {
			t.Errorf("normalizeEndpoint(%q) succeeded, want error", bad)
		}
	}
}

func TestDecodeNonce(t *testing.T) {
	raw := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	got, err := decodeNonce(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("decodeNonce = %x, want %x", got, raw)
	}
	if _, err := decodeNonce("!!!"); err == nil {
		t.Fatal("decodeNonce accepted invalid base64")
	}
}

// Compile-time reference to the wire version constant used by probes.
var _ = network.WireVersion
