package e2e_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	protocol "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net/e2e"
)

// TestE2EAuthorizedTCPShare drives the full local authorization chain for a
// TCP share end-to-end:
//
//  1. provider obtains a signed attestation from its own agent over the real
//     Unix-socket IPC path (the same wire path the Bun, Swift, and Go SDKs use)
//  2. Hub mints a ConnectionGrant authorizing the caller to reach the share
//  3. the caller's connection.Manager verifies the grant and installs the
//     authorized WireGuard peer (target key + destination /32 only)
//  4. the provider's enforcement.Manager installs the exact signed
//     (source, destination, tcp, port) firewall rule
//  5. the harness confirms the firewall admits the authorized tuple and
//     rejects every scan tuple (wrong port, wrong caller, wrong protocol)
func TestE2EAuthorizedTCPShare(t *testing.T) {
	const (
		resourceID  = "hnr-tcp"
		shareName   = "minecraft"
		tcpPort     = 25565
		destination = "100.96.0.20"
	)
	h := e2e.New(t)
	provider := h.Provider()
	caller := h.Caller()

	att := providerAttestation(t, provider, shareName, "tcp", "127.0.0.1", tcpPort)
	if att.Key != provider.Key {
		t.Fatalf("attestation key = %s, want %s", att.Key, provider.Key)
	}

	grant := h.IssueGrant(resourceID, "tcp", tcpPort)
	if err := caller.Connection.Connect(context.Background(), grant, h.Candidates(time.Now())); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	state, _ := caller.Adapter.State()
	if len(state.Peers) != 1 {
		t.Fatalf("installed peers = %d, want 1", len(state.Peers))
	}
	peer := state.Peers[0]
	if got := base64.StdEncoding.EncodeToString(peer.PublicKey); got != provider.WireGuardPubB64 {
		t.Fatalf("peer key = %s, want provider WireGuard key", got)
	}
	if len(peer.AllowedIPs) != 1 {
		t.Fatalf("allowed IPs = %v, want exactly one", peer.AllowedIPs)
	}
	wantDest := overlay32(destination)
	if peer.AllowedIPs[0] != wantDest {
		t.Fatalf("allowed IP = %s, want %s", peer.AllowedIPs[0], wantDest)
	}
	if err := provider.Enforce.Authorize(grant); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	now := time.Now()
	source := mustParseAddr(caller.OverlayAddress)
	dest := mustParseAddr(destination)
	if !provider.Allowed("tcp", source, dest, tcpPort, now) {
		t.Fatal("firewall denied authorized TCP tuple")
	}
	if provider.Allowed("tcp", source, dest, tcpPort+1, now) {
		t.Fatal("firewall admitted unshared port")
	}
	if provider.Allowed("udp", source, dest, tcpPort, now) {
		t.Fatal("firewall admitted UDP against a TCP share")
	}
	if provider.Allowed("tcp", mustParseAddr("100.96.0.99"), dest, tcpPort, now) {
		t.Fatal("firewall admitted spoofed caller address")
	}
}

// TestE2EAuthorizedUDPShare proves the same chain holds for UDP. The protocol
// field flows through every signature domain; a UDP grant must not be accepted
// as TCP and vice versa.
func TestE2EAuthorizedUDPShare(t *testing.T) {
	const (
		resourceID  = "hnr-udp"
		shareName   = "voice"
		udpPort     = 41200
		destination = "100.96.0.20"
	)
	h := e2e.New(t)
	provider := h.Provider()
	caller := h.Caller()

	att := providerAttestation(t, provider, shareName, "udp", "127.0.0.1", udpPort)
	if att.Protocol != "udp" {
		t.Fatalf("attestation protocol = %s", att.Protocol)
	}

	grant := h.IssueGrant(resourceID, "udp", udpPort)
	if err := caller.Connection.Connect(context.Background(), grant, h.Candidates(time.Now())); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := provider.Enforce.Authorize(grant); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	now := time.Now()
	source := mustParseAddr(caller.OverlayAddress)
	dest := mustParseAddr(destination)
	if !provider.Allowed("udp", source, dest, udpPort, now) {
		t.Fatal("firewall denied authorized UDP tuple")
	}
	if provider.Allowed("tcp", source, dest, udpPort, now) {
		t.Fatal("firewall admitted TCP against a UDP share")
	}
}

// TestE2EBlockedPortRejectsAcrossLayers proves that when the published share
// uses one port and the caller requests another, every agent layer rejects:
// the firewall has no matching rule (the attestation and grant were for the
// published port, not the scan port) and a grant for a different port cannot
// be minted without Hub signing. This is the "blocked ports" half of HN-310:
// the no-relay, fail-closed behavior.
func TestE2EBlockedPortRejectsAcrossLayers(t *testing.T) {
	const (
		publishedResource = "hnr-game"
		shareName         = "factorio"
		publishedPort     = 34197
		blockedPort       = 25565 // unrelated, not published
		destination       = "100.96.0.20"
	)
	h := e2e.New(t)
	provider := h.Provider()
	caller := h.Caller()

	// Provider attests and the Hub authorizes only the published port.
	_ = providerAttestation(t, provider, shareName, "tcp", "127.0.0.1", publishedPort)
	grant := h.IssueGrant(publishedResource, "tcp", publishedPort)
	if err := provider.Enforce.Authorize(grant); err != nil {
		t.Fatalf("Authorize published: %v", err)
	}

	now := time.Now()
	source := mustParseAddr(caller.OverlayAddress)
	dest := mustParseAddr(destination)

	// Firewall layer: the blocked port has no rule and is denied.
	if provider.Allowed("tcp", source, dest, blockedPort, now) {
		t.Fatal("firewall admitted non-published blocked port")
	}
	// WireGuard layer: a connection attempt for the blocked port cannot reuse
	// the published grant. Mutating the port breaks the signature, and the
	// verifier rejects the tampered grant before any candidate is checked.
	// The failure must be the grant rejection itself, never ErrDirectFailed
	// (which would imply the candidate path was reached).
	tampered := grant
	tampered.DestinationPort = blockedPort
	tampered.Signature = grant.Signature // leave stale signature on purpose
	err := caller.Connection.Connect(context.Background(), tampered, h.Candidates(now))
	if err == nil {
		t.Fatal("tampered grant was accepted")
	}
	if errors.Is(err, e2e.ErrDirectFailed) {
		t.Fatalf("tampered grant reached candidate checks: %v", err)
	}
	state, _ := caller.Adapter.State()
	if len(state.Peers) != 0 {
		t.Fatalf("tampered grant installed peers = %d, want 0", len(state.Peers))
	}
}

// providerAttestation performs the real local-agent IPC attestation flow over
// the provider's Unix socket: POST /challenge, sign the nonce with the
// provider's Hub identity, POST /attest. This is the wire path the
// hubconn/network Publisher uses in production.
func providerAttestation(t *testing.T, side *e2e.Side, shareName, protocolName, host string, port uint16) protocol.AgentAttestation {
	t.Helper()
	challengeBody := map[string]any{
		"serviceKey": side.ServiceKey, "shareName": shareName,
		"protocol": protocolName, "target": map[string]any{"host": host, "port": port},
	}
	challenge, status, err := postJSON(side.SocketPath(), "/challenge", challengeBody)
	if err != nil {
		t.Fatalf("%s challenge: %v", side.Name, err)
	}
	if status != http.StatusOK {
		t.Fatalf("%s challenge status = %d body = %v", side.Name, status, challenge)
	}
	nonce, _ := challenge["nonce"].(string)
	if nonce == "" {
		t.Fatalf("%s challenge returned empty nonce", side.Name)
	}
	signature := side.Identity.Sign([]byte(nonce))
	attestBody := map[string]any{
		"serviceKey": side.ServiceKey, "shareName": shareName,
		"protocol": protocolName, "target": map[string]any{"host": host, "port": port},
		"signature": signature,
	}
	resp, status, err := postJSON(side.SocketPath(), "/attest", attestBody)
	if err != nil {
		t.Fatalf("%s attest: %v", side.Name, err)
	}
	if status != http.StatusOK {
		t.Fatalf("%s attest status = %d body = %v", side.Name, status, resp)
	}
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("%s marshal attestation: %v", side.Name, err)
	}
	var att protocol.AgentAttestation
	if err := json.Unmarshal(encoded, &att); err != nil {
		t.Fatalf("%s decode attestation: %v", side.Name, err)
	}
	return att
}

// postJSON sends a JSON POST over a Unix-domain socket and returns the
// decoded body plus HTTP status.
func postJSON(socketPath, path string, body any) (map[string]any, int, error) {
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

func overlay32(address string) netip.Prefix {
	return netip.PrefixFrom(mustParseAddr(address), 32)
}

func mustParseAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}
