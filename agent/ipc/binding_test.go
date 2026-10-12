package ipc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/v57/hub-service-go/identity"
	"github.com/v57/hub-service-go/protocol"
)

func TestBindingProofBindsLocalAgentProfileConnectionAndCapability(t *testing.T) {
	agent, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	handler, err := NewAttestHandler(AttestHandlerOptions{Agent: agent})
	if err != nil {
		t.Fatalf("NewAttestHandler: %v", err)
	}
	key, _ := agent.PublicKeyBase64()
	proof, err := handler.BindingProof(BindingProofRequest{
		Version:      protocol.WireVersion,
		Type:         MessageBindingProof,
		Key:          key,
		ConnectionID: "connection-1",
		Nonce:        "hub-pro-nonce",
	})
	if err != nil {
		t.Fatalf("BindingProof: %v", err)
	}
	if proof.Key != key || proof.ConnectionID != "connection-1" {
		t.Fatalf("binding mismatch: %+v", proof)
	}
	if len(proof.Capabilities) != 1 || proof.Capabilities[0] != BootstrapCapability {
		t.Fatalf("capabilities = %v", proof.Capabilities)
	}
	der, _ := base64.StdEncoding.DecodeString(key)
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	publicKey := parsed.(ed25519.PublicKey)
	signature, _ := base64.StdEncoding.DecodeString(proof.Signature)
	if !ed25519.Verify(publicKey, []byte(bindingProofInput(proof)), signature) {
		t.Fatal("binding proof signature invalid")
	}
}

func TestBindingProofRejectsProfileSubstitution(t *testing.T) {
	agent, _ := identity.Generate()
	handler, _ := NewAttestHandler(AttestHandlerOptions{Agent: agent})
	_, err := handler.BindingProof(BindingProofRequest{
		Version:      protocol.WireVersion,
		Type:         MessageBindingProof,
		Key:          "different-profile",
		ConnectionID: "connection-1",
		Nonce:        "hub-pro-nonce",
	})
	if err == nil {
		t.Fatal("expected profile substitution rejection")
	}
}

func TestBindingProofUnixSocketEndpoint(t *testing.T) {
	agent, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewAttestHandler(AttestHandlerOptions{Agent: agent})
	if err != nil {
		t.Fatal(err)
	}
	socketPath, err := shortTempSocket()
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    handler,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errs := server.Start(ctx)
	t.Cleanup(func() {
		cancel()
		<-errs
	})
	deadline := time.Now().Add(time.Second)
	for {
		if connection, err := net.Dial("unix", socketPath); err == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("IPC socket did not become ready")
		}
		time.Sleep(time.Millisecond)
	}

	key, _ := agent.PublicKeyBase64()
	payload, _ := json.Marshal(BindingProofRequest{
		Version:      protocol.WireVersion,
		Type:         MessageBindingProof,
		Key:          key,
		ConnectionID: "connection-1",
		Nonce:        "hub-pro-nonce",
	})
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}}
	response, err := client.Post("http://unix/binding/proof", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var proof BindingProofResponse
	if err := json.NewDecoder(response.Body).Decode(&proof); err != nil {
		t.Fatal(err)
	}
	if proof.Key != key || proof.Nonce != "hub-pro-nonce" {
		t.Fatalf("unexpected proof: %+v", proof)
	}
}
