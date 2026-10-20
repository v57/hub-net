package invitation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/v57/hub-net-node/identity"
)

var testNow = time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)

func signedInput(t *testing.T) string {
	t.Helper()
	return testCode(t, testNow.Add(5*time.Minute), "")
}

func testCode(t *testing.T, expires time.Time, query string) string {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var expiry, nonce [4]byte
	binary.BigEndian.PutUint32(expiry[:], uint32(expires.Unix()))
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(publicKey) + "." + base64.RawURLEncoding.EncodeToString(expiry[:]) + "." + base64.RawURLEncoding.EncodeToString(nonce[:]) + query
	return payload + "/" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(payload)))
}

func TestCompactInvitation(t *testing.T) {
	code := testCode(t, testNow.Add(7*24*time.Hour), "?e=34.25.235.23")
	for _, input := range []string{code, URLPrefix + code} {
		decoded, err := Decode(input, testNow)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Node != "https://34.25.235.23" || decoded.Envelope.InvitingKey == "" || decoded.Envelope.TokenID == "" {
			t.Fatalf("decoded=%+v", decoded)
		}
	}
	if _, err := Decode("A"+code[1:], testNow); err == nil {
		t.Fatal("tampered code accepted")
	}
	if _, err := Decode(code, testNow.Add(7*24*time.Hour)); err == nil {
		t.Fatal("expired code accepted")
	}
	if _, err := Decode(testCode(t, testNow.Add(MaxLifetime+time.Second), "?e=34.25.235.23"), testNow); err == nil {
		t.Fatal("oversized lifetime accepted")
	}
}

func TestInvitationWithoutNodeIsRefused(t *testing.T) {
	// There is no built-in node: older codes without ?e= named the dead
	// hub.v57.dev/node.
	_, err := Decode(signedInput(t), testNow)
	var invitationError *Error
	if !errors.As(err, &invitationError) || invitationError.Code != "invite_missing_node" {
		t.Fatalf("Decode without a node: %v", err)
	}
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCode(id, ""); err == nil {
		t.Fatal("created an invitation without a node")
	}
	code, err := CreateCode(id, "ws://192.168.65.4:1964")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(code, time.Now())
	if err != nil || decoded.Node != "ws://192.168.65.4:1964" {
		t.Fatalf("decoded %+v, %v", decoded, err)
	}
}
