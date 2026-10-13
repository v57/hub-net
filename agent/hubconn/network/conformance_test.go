package network_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/v57/hub-net-node/identity"
	protocol "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net/hubconn/network"
)

func mustIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id
}

// TestShareReplacementMatchesSharedFixture (HN-076) builds a wire share with
// the same fields as the cross-language contract fixture and verifies the Go
// SDK produces byte-identical JSON for the share payload. Bun, Swift, and Go
// all consume/produce this shape.
func TestShareReplacementMatchesSharedFixture(t *testing.T) {
	fixturePath := filepath.Join("testdata", "shares-replace.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var envelope struct {
		Payload protocol.SharesReplacePayload `json:"payload"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	expectedShare := envelope.Payload.Shares[0]

	// Reconstruct the same share through the Go SDK path.
	share := network.Share{
		Name:     "s3",
		Protocol: network.ProtocolTCP,
		Host:     "127.0.0.1",
		Port:     9001,
		Policy:   &network.Policy{Mode: network.PolicyGroup, Group: "editors"},
	}
	attestation := &network.Attestation{
		Version:       protocol.WireVersion,
		AttestationID: "att-1",
		ServiceKey:    "service-key",
		Key:           "agent-key",
		ShareName:     "s3",
		Protocol:      "tcp",
		Target:        protocol.LocalTarget{Host: "127.0.0.1", Port: 9001},
		IssuedAt:      "2026-07-25T00:00:00.000Z",
		ExpiresAt:     "2026-07-25T00:05:00.000Z",
		Signature:     "c2lnbmF0dXJl",
	}
	publisher := network.New(network.Options{})
	payload, err := publisher.BuildReplacePayloadForTest([]network.Share{share}, func(network.Share, string, network.Signer) (*network.Attestation, error) {
		return attestation, nil
	}, "service-key")
	if err != nil {
		t.Fatalf("BuildReplacePayloadForTest: %v", err)
	}
	if len(payload.Shares) != 1 {
		t.Fatalf("expected 1 share, got %d", len(payload.Shares))
	}
	encoded, err := json.Marshal(payload.Shares[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	expected, err := json.Marshal(expectedShare)
	if err != nil {
		t.Fatalf("marshal expected: %v", err)
	}
	if string(encoded) != string(expected) {
		t.Fatalf("wire share mismatch\nwant: %s\ngot:  %s", expected, encoded)
	}
}

// TestAuthHeaderMatchesBunTokenShape verifies the Hub auth header token the Go
// SDK produces matches the Bun keychain format: key.{pub}.{sig}.{expiry}
func TestAuthHeaderMatchesBunTokenShape(t *testing.T) {
	id := mustIdentity(t)
	token, err := id.AuthToken(10 * time.Second)
	if err != nil {
		t.Fatalf("AuthToken: %v", err)
	}
	parts := splitDot(token)
	if len(parts) != 4 || parts[0] != "key" {
		t.Fatalf("token %q does not match Bun key.{pub}.{sig}.{expiry}", token)
	}
}

func splitDot(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
