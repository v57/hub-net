package network

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	protocol "github.com/v57/hub-net-node/models"
)

// fakeSigner records the nonce it was asked to sign.
type fakeSigner struct{ last string }

func (f *fakeSigner) SignChallenge(nonce string) (string, error) {
	f.last = nonce
	return "sig-" + nonce, nil
}

// stubSender captures the last network/shares/replace payload and returns a
// canned publication set sized to the declared shares.
type stubSender struct {
	lastPath     string
	lastShares   []protocol.NetworkShare
	publications []Publication
	err          error
}

func (s *stubSender) Send(path string, body any, contextValue ...any) (any, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.lastPath = path
	encoded, _ := json.Marshal(body)
	var payload protocol.SharesReplacePayload
	_ = json.Unmarshal(encoded, &payload)
	s.lastShares = payload.Shares
	if s.publications == nil {
		s.publications = make([]Publication, len(payload.Shares))
		for i := range payload.Shares {
			s.publications[i] = Publication{
				Version:        WireVersion,
				ResourceID:     "hnr1_test",
				ProviderID:     "pvd_test",
				Protocol:       payload.Shares[i].Protocol,
				OverlayAddress: "10.0.0.1",
				Port:           1000 + uint16(i),
			}
		}
	}
	return map[string]any{"shares": s.publications}, nil
}

func validAttestation(share Share, serviceKey string) *Attestation {
	return &Attestation{
		Version:       WireVersion,
		AttestationID: "att_test",
		ServiceKey:    serviceKey,
		Key:           "agnt_test",
		ShareName:     share.Name,
		Protocol:      string(share.Protocol),
		Target:        protocol.LocalTarget{Host: share.Host, Port: share.Port},
		IssuedAt:      time.Now().Format(time.RFC3339),
		ExpiresAt:     time.Now().Add(time.Hour).Format(time.RFC3339),
		Signature:     "sig",
	}
}

func TestPublishWithCustomProviderRoundTrip(t *testing.T) {
	signer := &fakeSigner{}
	share := Share{Name: "s3", Protocol: ProtocolTCP, Host: "127.0.0.1", Port: 8080, Policy: &Policy{Mode: PolicyHub}}
	var providedShare Share
	provider := func(s Share, serviceKey string, _ Signer) (*Attestation, error) {
		providedShare = s
		return validAttestation(s, serviceKey), nil
	}
	publisher := New(Options{AttestationProvider: provider})
	sender := &stubSender{}

	publications, err := publisher.Publish(context.Background(), share, "svc_key", signer, sender)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if providedShare.Name != "s3" {
		t.Fatalf("provider did not see share")
	}
	if sender.lastPath != "network/shares/replace" {
		t.Fatalf("path = %q", sender.lastPath)
	}
	if len(sender.lastShares) != 1 || sender.lastShares[0].Name != "s3" {
		t.Fatalf("wire shares = %+v", sender.lastShares)
	}
	if sender.lastShares[0].Attestation.ServiceKey != "svc_key" {
		t.Fatalf("attestation not embedded")
	}
	if sender.lastShares[0].Policy.Mode != string(PolicyHub) {
		t.Fatalf("policy mode = %v", sender.lastShares[0].Policy.Mode)
	}
	if len(publications) != 1 || publications[0].Port != 1000 {
		t.Fatalf("publications = %+v", publications)
	}
	if pub, ok := publisher.Publication("s3"); !ok || pub.Port != 1000 {
		t.Fatalf("stored publication missing")
	}
}

func TestPublishRollbackOnError(t *testing.T) {
	signer := &fakeSigner{}
	publisher := New(Options{AttestationProvider: func(Share, string, Signer) (*Attestation, error) {
		return nil, errors.New("boom")
	}})
	_, err := publisher.Publish(context.Background(), Share{Name: "x"}, "svc", signer, &stubSender{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if publisher.HasShares() {
		t.Fatalf("share should be rolled back on error")
	}
}

func TestRemoveRestoresShareOnFailure(t *testing.T) {
	signer := &fakeSigner{}
	publisher := New(Options{AttestationProvider: func(s Share, _ string, _ Signer) (*Attestation, error) {
		return validAttestation(s, "svc"), nil
	}})
	if _, err := publisher.Publish(context.Background(), Share{Name: "x", Protocol: ProtocolTCP, Host: "h", Port: 1}, "svc", signer, &stubSender{}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	failing := &stubSender{err: errors.New("hub down")}
	_, err := publisher.Remove(context.Background(), "x", "svc", signer, failing)
	if err == nil {
		t.Fatalf("expected error")
	}
	if _, ok := publisher.DeclaredShare("x"); !ok {
		t.Fatalf("share should be restored after failed remove")
	}
}

func TestValidateAttestationRejectsMismatch(t *testing.T) {
	share := Share{Name: "s3", Protocol: ProtocolTCP, Host: "127.0.0.1", Port: 8080}
	att := validAttestation(share, "svc")
	att.Target.Port = 9999
	if err := validateAttestation(att, share, "svc"); err == nil {
		t.Fatalf("expected mismatch error")
	}
}

func TestDefaultPolicyIsPrivate(t *testing.T) {
	share := Share{Name: "x", Protocol: ProtocolUDP, Host: "h", Port: 1}
	wire := toWireShare(share, validAttestation(share, "svc"))
	if wire.Policy == nil || wire.Policy.Mode != string(PolicyPrivate) {
		t.Fatalf("default policy = %+v", wire.Policy)
	}
}

// TestAgentPostViaUnixSocket exercises the real local-agent IPC flow against
// a stub HTTP server listening on a Unix socket.
func TestAgentPostViaUnixSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := dir + "/agent.sock"
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"nonce": "abc123"})
	})
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(validAttestation(Share{Name: "s3", Protocol: ProtocolTCP, Host: "127.0.0.1", Port: 9000}, "svc_key"))
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()

	signer := &fakeSigner{}
	publisher := New(Options{AgentSocket: socketPath, AgentTimeout: time.Second})
	attestation, err := publisher.requestAttestation(context.Background(), Share{Name: "s3", Protocol: ProtocolTCP, Host: "127.0.0.1", Port: 9000}, "svc_key", signer)
	if err != nil {
		t.Fatalf("requestAttestation: %v", err)
	}
	if signer.last != "abc123" {
		t.Fatalf("signer got %q, want abc123", signer.last)
	}
	if attestation.ServiceKey != "svc_key" {
		t.Fatalf("attestation serviceKey = %q", attestation.ServiceKey)
	}
}

func TestAgentUnavailableWhenSocketMissing(t *testing.T) {
	publisher := New(Options{AgentSocket: "/does/not/exist.sock", AgentTimeout: 100 * time.Millisecond})
	_, err := publisher.requestAttestation(context.Background(), Share{Name: "x"}, "svc", &fakeSigner{})
	var agentErr *LocalAgentError
	if !errors.As(err, &agentErr) {
		t.Fatalf("expected LocalAgentError, got %T %v", err, err)
	}
	if agentErr.Code != AgentUnavailable && agentErr.Code != AgentTimeout {
		t.Fatalf("code = %q", agentErr.Code)
	}
}
