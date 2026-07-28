package ipc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/v57/hub-service-go/identity"
	"github.com/v57/hub-service-go/protocol"
)

// newTestServer spins up a socket-bound Server backed by a real AttestHandler
// keyed to agent. The peer-credential check is relaxed for tests since the
// test client connects from an arbitrary goroutine context.
func newTestServer(t *testing.T, agent *identity.Identity, policy LocalTargetPolicy) (*Server, string) {
	t.Helper()
	handler, err := NewAttestHandler(AttestHandlerOptions{
		Agent:          agent,
		Policy:         policy,
		AttestationTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewAttestHandler: %v", err)
	}
	return newTestServerWithHandler(t, handler)
}

func newTestServerWithHandler(t *testing.T, handler *AttestHandler) (*Server, string) {
	t.Helper()
	// macOS caps Unix socket paths near 104 bytes; t.TempDir() plus a long
	// test name overflows that. Use a short random path under the system
	// temp dir instead.
	socketPath, err := shortTempSocket()
	if err != nil {
		t.Fatalf("short temp socket: %v", err)
	}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    handler,
		PeerPolicy: PeerPolicy{AllowAnyLocal: true},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	errs := server.Start(context.Background())
	t.Cleanup(func() {
		_ = server.Close(context.Background())
		<-errs
	})
	if !waitForBind(server) {
		t.Fatalf("server did not bind")
	}
	return server, socketPath
}

// shortTempSocket returns a short, unique Unix socket path under os.TempDir.
func shortTempSocket() (string, error) {
	for i := 0; i < 8; i++ {
		var buf [6]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return "", err
		}
		path := filepath.Join(os.TempDir(), "hn-"+hex.EncodeToString(buf[:])+".sock")
		if len(path) > 90 { // stay well under the macOS 104-byte cap
			continue
		}
		return path, nil
	}
	return "", errors.New("could not allocate short socket path")
}

func waitForBind(server *Server) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if server.Addr() != nil {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// attestationFlow mirrors the hub-service-go Publisher.requestAttestation wire
// contract (Bun, Swift, and Go clients all send the same shapes): POST
// /challenge, sign the returned nonce, POST /attest without echoing nonce.
func attestationFlow(t *testing.T, socketPath, serviceKey, shareName, proto, host string, port uint16, sign func(string) string) (protocol.AgentAttestation, int, error) {
	t.Helper()
	body := map[string]any{
		"serviceKey": serviceKey,
		"shareName":  shareName,
		"protocol":   proto,
		"target":     map[string]any{"host": host, "port": port},
	}
	challenge, status, err := postJSON(t, socketPath, "/challenge", body)
	if err != nil {
		return protocol.AgentAttestation{}, status, err
	}
	if status != http.StatusOK {
		return protocol.AgentAttestation{}, status, nil
	}
	nonce, _ := challenge["nonce"].(string)
	attestBody := map[string]any{
		"serviceKey": serviceKey,
		"shareName":  shareName,
		"protocol":   proto,
		"target":     map[string]any{"host": host, "port": port},
		"signature":  sign(nonce),
	}
	attestResp, status, err := postJSON(t, socketPath, "/attest", attestBody)
	if err != nil {
		return protocol.AgentAttestation{}, status, err
	}
	if status != http.StatusOK {
		return protocol.AgentAttestation{}, status, nil
	}
	// The /attest response carries the attestation fields at the top level.
	encoded, _ := json.Marshal(attestResp)
	var att protocol.AgentAttestation
	if err := json.Unmarshal(encoded, &att); err != nil {
		t.Fatalf("decode attestation: %v", err)
	}
	return att, status, nil
}

func TestE2EFullChallengeAttestFlow(t *testing.T) {
	agent, err := identity.Generate()
	if err != nil {
		t.Fatalf("agent identity: %v", err)
	}
	_, socketPath := newTestServer(t, agent, DefaultTargetPolicy())

	service, err := identity.Generate()
	if err != nil {
		t.Fatalf("service identity: %v", err)
	}
	serviceKey, err := service.PublicKeyBase64()
	if err != nil {
		t.Fatalf("service key: %v", err)
	}

	att, status, err := attestationFlow(t, socketPath, serviceKey, "s3", "tcp", "127.0.0.1", 9000, signString(service))
	if err != nil {
		t.Fatalf("flow: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}

	agentPub, err := parseSPKIPublicKey(att.AgentKey)
	if err != nil {
		t.Fatalf("parse agentKey: %v", err)
	}
	ok, err := protocol.VerifyEnvelope(protocol.PurposeAgentAttestation, att, agentPub, att.Signature)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatalf("attestation signature invalid")
	}
	if att.ServiceKey != serviceKey || att.ShareName != "s3" || att.Protocol != "tcp" ||
		att.Target.Host != "127.0.0.1" || att.Target.Port != 9000 {
		t.Fatalf("attestation fields mismatch: %+v", att)
	}
	if att.AgentKey == "" || att.AttestationID == "" || att.IssuedAt == "" || att.ExpiresAt == "" {
		t.Fatalf("attestation missing fields: %+v", att)
	}
}

func TestE2ECompositeKeyTwoShares(t *testing.T) {
	agent, _ := identity.Generate()
	_, socketPath := newTestServer(t, agent, DefaultTargetPolicy())
	service, _ := identity.Generate()
	serviceKey, _ := service.PublicKeyBase64()

	// Request both challenges before either attest. Distinct composite keys
	// must keep the pending entries independent: a share B attestation must
	// not consume share A's nonce.
	if _, _, err := postJSON(t, socketPath, "/challenge", map[string]any{
		"serviceKey": serviceKey, "shareName": "a", "protocol": "tcp",
		"target": map[string]any{"host": "127.0.0.1", "port": 9001},
	}); err != nil {
		t.Fatalf("challenge A: %v", err)
	}
	if _, _, err := postJSON(t, socketPath, "/challenge", map[string]any{
		"serviceKey": serviceKey, "shareName": "b", "protocol": "tcp",
		"target": map[string]any{"host": "127.0.0.1", "port": 9002},
	}); err != nil {
		t.Fatalf("challenge B: %v", err)
	}

	attA, status, err := attestationFlow(t, socketPath, serviceKey, "a", "tcp", "127.0.0.1", 9001, signString(service))
	if err != nil || status != http.StatusOK {
		t.Fatalf("attest A: status=%d err=%v", status, err)
	}
	if attA.ShareName != "a" {
		t.Fatalf("attest A share = %s", attA.ShareName)
	}
	attB, status, err := attestationFlow(t, socketPath, serviceKey, "b", "tcp", "127.0.0.1", 9002, signString(service))
	if err != nil || status != http.StatusOK {
		t.Fatalf("attest B: status=%d err=%v", status, err)
	}
	if attB.ShareName != "b" {
		t.Fatalf("attest B share = %s", attB.ShareName)
	}
}

func TestE2ERemoteTargetRejected(t *testing.T) {
	agent, _ := identity.Generate()
	_, socketPath := newTestServer(t, agent, DefaultTargetPolicy())
	service, _ := identity.Generate()
	serviceKey, _ := service.PublicKeyBase64()

	_, status, _ := attestationFlow(t, socketPath, serviceKey, "remote", "udp", "8.8.8.8", 53, signString(service))
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (remote_target)", status)
	}
}

func TestE2EExpiredNonceRejected(t *testing.T) {
	now := time.Now()
	agent, _ := identity.Generate()
	handler, err := NewAttestHandler(AttestHandlerOptions{
		Agent:          agent,
		Policy:         DefaultTargetPolicy(),
		AttestationTTL: time.Minute,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	_, socketPath := newTestServerWithHandler(t, handler)

	service, _ := identity.Generate()
	serviceKey, _ := service.PublicKeyBase64()
	challenge, status, err := postJSON(t, socketPath, "/challenge", map[string]any{
		"serviceKey": serviceKey, "shareName": "x", "protocol": "tcp",
		"target": map[string]any{"host": "127.0.0.1", "port": 1234},
	})
	if err != nil || status != http.StatusOK {
		t.Fatalf("challenge: status=%d err=%v", status, err)
	}
	nonce, _ := challenge["nonce"].(string)

	// Advance past the nonce TTL so the pending entry is expired.
	handler.SetNowForTest(func() time.Time { return now.Add(ChallengeTTL + time.Second) })

	resp, status, err := postJSON(t, socketPath, "/attest", map[string]any{
		"serviceKey": serviceKey, "shareName": "x", "protocol": "tcp",
		"target":    map[string]any{"host": "127.0.0.1", "port": 1234},
		"signature": service.Sign([]byte(nonce)),
	})
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if code := errorCode(resp); code != "invalid_nonce" {
		t.Fatalf("code = %q, want invalid_nonce", code)
	}
}

func TestE2EBadSignatureRejected(t *testing.T) {
	agent, _ := identity.Generate()
	_, socketPath := newTestServer(t, agent, DefaultTargetPolicy())
	service, _ := identity.Generate()
	serviceKey, _ := service.PublicKeyBase64()

	// Sign a different nonce than the agent issued; verification must fail.
	tamper := func(nonce string) string { return service.Sign([]byte(nonce + "tampered")) }
	_, status, _ := attestationFlow(t, socketPath, serviceKey, "s", "tcp", "127.0.0.1", 9999, tamper)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (invalid_signature)", status)
	}
}

func TestE2EWrongServiceKeyCannotAttest(t *testing.T) {
	agent, _ := identity.Generate()
	_, socketPath := newTestServer(t, agent, DefaultTargetPolicy())
	service, _ := identity.Generate()
	other, _ := identity.Generate()
	serviceKey, _ := service.PublicKeyBase64()
	otherKey, _ := other.PublicKeyBase64()

	// Challenge issued under serviceKey, attested under otherKey. Because the
	// composite key includes serviceKey, the lookup misses and the request is
	// rejected as invalid_nonce. A second service cannot obtain an attestation
	// for a share it never challenged.
	body := map[string]any{
		"serviceKey": serviceKey, "shareName": "s", "protocol": "tcp",
		"target": map[string]any{"host": "127.0.0.1", "port": 7000},
	}
	if _, status, err := postJSON(t, socketPath, "/challenge", body); err != nil || status != http.StatusOK {
		t.Fatalf("challenge: status=%d err=%v", status, err)
	}
	resp, status, _ := postJSON(t, socketPath, "/attest", map[string]any{
		"serviceKey": otherKey, "shareName": "s", "protocol": "tcp",
		"target":    map[string]any{"host": "127.0.0.1", "port": 7000},
		"signature": "0000",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	code := errorCode(resp)
	if code != "invalid_nonce" && code != "invalid_signature" && code != "forbidden" {
		t.Fatalf("code = %q, want a rejection code", code)
	}
}

// TestHandlerForbiddenOnSwappedNonce covers the in-process path where a
// client echoes the nonce: a challenge bound to serviceKey, redeemed with the
// same nonce but a different serviceKey, must yield forbidden (not
// invalid_nonce), so the wire code distinguishes a key swap from an unknown
// challenge.
func TestHandlerForbiddenOnSwappedNonce(t *testing.T) {
	agent, _ := identity.Generate()
	service, _ := identity.Generate()
	other, _ := identity.Generate()
	serviceKey, _ := service.PublicKeyBase64()
	otherKey, _ := other.PublicKeyBase64()

	handler, _ := NewAttestHandler(AttestHandlerOptions{
		Agent:  agent,
		Policy: DefaultTargetPolicy(),
	})
	target := protocol.LocalTarget{Host: "127.0.0.1", Port: 7000}
	challenge, err := handler.Challenge(ChallengeRequest{
		ServiceKey: serviceKey, ShareName: "s", Protocol: "tcp", Target: target,
	})
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	_, err = handler.Attest(AttestRequest{
		ServiceKey: otherKey, ShareName: "s", Protocol: "tcp", Target: target,
		Nonce:     challenge.Nonce,
		Signature: other.Sign([]byte(challenge.Nonce)),
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	var ipcErr *ipcError
	if !errors.As(err, &ipcErr) || ipcErr.Code() != "forbidden" {
		t.Fatalf("err = %v, want forbidden", err)
	}
}

func TestE2EStatusReady(t *testing.T) {
	agent, _ := identity.Generate()
	_, socketPath := newTestServer(t, agent, DefaultTargetPolicy())
	resp, status, err := postJSON(t, socketPath, "/status", map[string]any{})
	if err != nil || status != http.StatusOK {
		t.Fatalf("status: code=%d err=%v", status, err)
	}
	ready, _ := resp["ready"].(bool)
	if !ready {
		t.Fatalf("not ready: %+v", resp)
	}
	if resp["agentKey"] == nil {
		t.Fatalf("empty agentKey")
	}
}

func TestUnknownPathReturns404(t *testing.T) {
	agent, _ := identity.Generate()
	_, socketPath := newTestServer(t, agent, DefaultTargetPolicy())
	_, status, _ := postJSON(t, socketPath, "/bogus", map[string]any{})
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
}

func TestWrongMethodReturns405(t *testing.T) {
	agent, _ := identity.Generate()
	_, socketPath := newTestServer(t, agent, DefaultTargetPolicy())
	resp, err := doUnix(t, http.MethodGet, socketPath, "/challenge", nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	agent, _ := identity.Generate()
	_, socketPath := newTestServer(t, agent, DefaultTargetPolicy())
	huge := strings.Repeat("x", MaxRequestBytes+1)
	_, status, _ := postJSON(t, socketPath, "/challenge", map[string]any{"serviceKey": huge})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
}

func TestSocketFileRemovedOnClose(t *testing.T) {
	agent, _ := identity.Generate()
	handler, _ := NewAttestHandler(AttestHandlerOptions{
		Agent:  agent,
		Policy: DefaultTargetPolicy(),
	})
	socketPath, err := shortTempSocket()
	if err != nil {
		t.Fatalf("short temp socket: %v", err)
	}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    handler,
		PeerPolicy: PeerPolicy{AllowAnyLocal: true},
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	errs := server.Start(context.Background())
	if !waitForBind(server) {
		t.Fatalf("server did not bind")
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	<-errs
	if _, statErr := os.Stat(socketPath); !os.IsNotExist(statErr) {
		t.Fatalf("socket still present after close: %v", statErr)
	}
}

// --- helpers --------------------------------------------------------------

func signString(id *identity.Identity) func(string) string {
	return func(s string) string { return id.Sign([]byte(s)) }
}

func postJSON(t *testing.T, socketPath, path string, body any) (map[string]any, int, error) {
	t.Helper()
	enc, _ := json.Marshal(body)
	resp, err := doUnix(t, http.MethodPost, socketPath, path, bytes.NewReader(enc))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	_ = json.Unmarshal(payload, &decoded)
	return decoded, resp.StatusCode, nil
}

func doUnix(t *testing.T, method, socketPath, path string, body io.Reader) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(method, "http://localhost"+path, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("content-type", "application/json")
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 2 * time.Second,
	}
	return client.Do(req)
}

func errorCode(body map[string]any) string {
	if body == nil {
		return ""
	}
	if e, ok := body["error"].(map[string]any); ok {
		if c, ok := e["code"].(string); ok {
			return c
		}
	}
	return ""
}
