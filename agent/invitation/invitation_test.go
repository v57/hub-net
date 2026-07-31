package invitation

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/v57/hub-service-go/protocol"
)

var testNow = time.Date(2026, 7, 29, 0, 5, 0, 0, time.UTC)

func signedInput(t *testing.T) string {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	envelope := Envelope{
		Version: 1, SignatureDomain: Domain,
		TokenID:              base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		IssuedAt:             "2026-07-29T00:00:00.000Z",
		ExpiresAt:            "2026-07-29T00:10:00.000Z",
		HubKey:               base64.StdEncoding.EncodeToString(publicDER),
		InvitingAgentKey:     base64.StdEncoding.EncodeToString(publicDER),
		InvitingAgentAddress: "100.96.0.2",
		HubProHost:           "100.96.0.1",
		Scopes:               expectedScopes,
	}
	envelope.Signature, err = protocol.SignEnvelope(protocol.PurposeNetworkInvitation, envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := protocol.CanonicalJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(canonical))
}

func TestDecodeCanonicalInvitation(t *testing.T) {
	code := signedInput(t)
	for _, input := range []string{code, URLPrefix + code} {
		decoded, err := Decode(input, testNow)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Node != DefaultNode || decoded.Envelope.HubProHost != "100.96.0.1" {
			t.Fatalf("unexpected decode: %#v", decoded)
		}
	}
}

func TestDecodeSharedGoldenInvitationFixture(t *testing.T) {
	raw, err := os.ReadFile("../../../hub-pro/src/network/testdata/invitation-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Code string `json:"code"`
		URL  string `json:"url"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{fixture.Code, fixture.URL} {
		decoded, err := Decode(input, testNow)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Code != fixture.Code || decoded.URL != fixture.URL || decoded.Node != DefaultNode {
			t.Fatalf("shared fixture mismatch: %#v", decoded)
		}
	}
}

func TestDecodeCanonicalCustomNode(t *testing.T) {
	code := signedInput(t)
	raw, _ := base64.RawURLEncoding.DecodeString(code)
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Node = "https://node.example.test/bootstrap"
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	var err error
	envelope.Signature, err = protocol.SignEnvelope(
		protocol.PurposeNetworkInvitation,
		envelope,
		ed25519.NewKeyFromSeed(seed),
	)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := protocol.CanonicalJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(base64.RawURLEncoding.EncodeToString([]byte(canonical)), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Node != envelope.Node {
		t.Fatalf("node = %q, want %q", decoded.Node, envelope.Node)
	}
}

func TestDecodeRejectsBeforeNetworkingInputs(t *testing.T) {
	code := signedInput(t)
	raw, _ := base64.RawURLEncoding.DecodeString(code)
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["hubProHost"] = "100.96.0.9"
	tampered, _ := protocol.CanonicalJSON(envelope)
	delete(envelope, "signature")
	missing, _ := protocol.CanonicalJSON(envelope)

	cases := []struct {
		name, input, code string
		now               time.Time
	}{
		{"padding", code + "=", "invite_non_canonical", testNow},
		{"wrong URL", "https://example.test/" + code, "invite_malformed", testNow},
		{"tamper", base64.RawURLEncoding.EncodeToString([]byte(tampered)), "invite_invalid_signature", testNow},
		{"expired", code, "invite_expired", testNow.Add(6 * time.Minute)},
		{"duplicate", base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(raw), `{"expiresAt"`, `{"version":1,"expiresAt"`, 1))), "invite_malformed", testNow},
		{"missing field", base64.RawURLEncoding.EncodeToString([]byte(missing)), "invite_malformed", testNow},
		{"unknown field", mutateCanonical(t, raw, func(value map[string]any) { value["critical"] = true }), "invite_malformed", testNow},
		{"wrong version", mutateCanonical(t, raw, func(value map[string]any) { value["version"] = 2 }), "invite_unsupported_version", testNow},
		{"future issued", code, "invite_invalid_time", testNow.Add(-10 * time.Minute)},
		{"wrong audience", mutateCanonical(t, raw, func(value map[string]any) { value["scopes"] = []any{} }), "invite_wrong_audience", testNow},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(test.input, test.now)
			var invitationErr *Error
			if !errors.As(err, &invitationErr) || invitationErr.Code != test.code {
				t.Fatalf("got %v, want %s", err, test.code)
			}
		})
	}
}

func mutateCanonical(t *testing.T, raw []byte, mutate func(map[string]any)) string {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	canonical, err := protocol.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(canonical))
}
