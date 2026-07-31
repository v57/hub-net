// Package invitation validates Hub Network join invitations before networking.
package invitation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/v57/hub-service-go/protocol"
)

const (
	URLPrefix   = "hub://net/join/"
	DefaultNode = "https://hub.v57.dev/node"
	Domain      = "hub-network/invitation/v1"
	Lifetime    = 10 * time.Minute
	MaxCodeSize = 16 * 1024
)

type Scope struct {
	Audience string   `json:"audience"`
	Actions  []string `json:"actions"`
}

type Envelope struct {
	Version              int     `json:"version"`
	SignatureDomain      string  `json:"signatureDomain"`
	TokenID              string  `json:"tokenId"`
	IssuedAt             string  `json:"issuedAt"`
	ExpiresAt            string  `json:"expiresAt"`
	HubKey               string  `json:"hubKey"`
	InvitingAgentKey     string  `json:"invitingAgentKey"`
	InvitingAgentAddress string  `json:"invitingAgentAddress"`
	HubProHost           string  `json:"hubProHost"`
	Node                 string  `json:"node,omitempty"`
	Scopes               []Scope `json:"scopes"`
	Signature            string  `json:"signature"`
}

type Decoded struct {
	Envelope Envelope
	Node     string
	Code     string
	URL      string
}

type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(code, message string) error { return &Error{Code: code, Err: errors.New(message)} }

var expectedScopes = []Scope{
	{Audience: "node", Actions: []string{"bootstrap-rendezvous"}},
	{Audience: "inviting-agent", Actions: []string{"bootstrap-peer"}},
	{Audience: "joiner", Actions: []string{"bootstrap-peer", "enroll-profile", "read-hub-header"}},
	{Audience: "hub-pro", Actions: []string{"enroll-profile"}},
}

// Decode validates canonical encoding, schema, time, addresses, scopes, and Hub signature.
func Decode(input string, now time.Time) (Decoded, error) {
	code, err := codeFromInput(input)
	if err != nil {
		return Decoded{}, err
	}
	if len(code) > MaxCodeSize || strings.Contains(code, "=") || code == "" {
		return Decoded{}, fail("invite_non_canonical", "invitation must use bounded unpadded base64url")
	}
	raw, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != code {
		return Decoded{}, fail("invite_non_canonical", "invitation base64url is not canonical")
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return Decoded{}, fail("invite_malformed", err.Error())
	}
	var generic map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		return Decoded{}, fail("invite_malformed", "invitation payload is not JSON")
	}
	canonical, err := protocol.CanonicalJSON(generic)
	if err != nil || canonical != string(raw) {
		return Decoded{}, fail("invite_non_canonical", "invitation JSON is not canonical")
	}
	allowed := map[string]bool{
		"version": true, "signatureDomain": true, "tokenId": true, "issuedAt": true,
		"expiresAt": true, "hubKey": true, "invitingAgentKey": true,
		"invitingAgentAddress": true, "hubProHost": true, "node": true,
		"scopes": true, "signature": true,
	}
	for key := range generic {
		if !allowed[key] {
			return Decoded{}, fail("invite_malformed", "unknown field "+key)
		}
	}
	if len(generic) != 11 && len(generic) != 12 {
		return Decoded{}, fail("invite_malformed", "invitation fields are incomplete")
	}
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Decoded{}, fail("invite_malformed", "invalid invitation envelope")
	}
	if envelope.Version != 1 || envelope.SignatureDomain != Domain {
		return Decoded{}, fail("invite_unsupported_version", "unsupported invitation version")
	}
	if err := validateEnvelope(envelope, now); err != nil {
		return Decoded{}, err
	}
	node := DefaultNode
	if envelope.Node != "" {
		normalized, err := normalizeNode(envelope.Node)
		if err != nil || normalized != envelope.Node || normalized == DefaultNode {
			return Decoded{}, fail("invite_non_canonical", "rendezvous node is not canonical")
		}
		node = normalized
	}
	return Decoded{Envelope: envelope, Node: node, Code: code, URL: URLPrefix + code}, nil
}

func validateEnvelope(envelope Envelope, now time.Time) error {
	token, err := base64.RawURLEncoding.DecodeString(envelope.TokenID)
	if err != nil || len(token) != 32 || base64.RawURLEncoding.EncodeToString(token) != envelope.TokenID {
		return fail("invite_malformed", "tokenId must contain 256 bits")
	}
	issued, err1 := time.Parse(time.RFC3339Nano, envelope.IssuedAt)
	expires, err2 := time.Parse(time.RFC3339Nano, envelope.ExpiresAt)
	if err1 != nil || err2 != nil || expires.Sub(issued) != Lifetime || issued.After(now.Add(protocol.MaxClockSkew)) {
		return fail("invite_invalid_time", "invitation lifetime is invalid")
	}
	if !expires.After(now) {
		return fail("invite_expired", "invitation has expired")
	}
	if !scopesEqual(envelope.Scopes, expectedScopes) {
		return fail("invite_wrong_audience", "invitation bootstrap scopes are invalid")
	}
	if _, err := netip.ParseAddr(envelope.InvitingAgentAddress); err != nil {
		return fail("invite_malformed", "invitingAgentAddress must be an IP address")
	}
	if _, err := netip.ParseAddr(envelope.HubProHost); err != nil {
		return fail("invite_malformed", "hubProHost must be an IP address")
	}
	keyDER, err := base64.StdEncoding.Strict().DecodeString(envelope.HubKey)
	if err != nil {
		return fail("invite_malformed", "hubKey must be canonical base64")
	}
	publicAny, err := x509.ParsePKIXPublicKey(keyDER)
	publicKey, ok := publicAny.(ed25519.PublicKey)
	if err != nil || !ok {
		return fail("invite_malformed", "hubKey must be an Ed25519 SPKI key")
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(envelope.InvitingAgentKey); err != nil {
		return fail("invite_malformed", "invitingAgentKey must be canonical base64")
	}
	valid, err := protocol.VerifyEnvelope(protocol.PurposeNetworkInvitation, envelope, publicKey, envelope.Signature)
	if err != nil || !valid {
		return fail("invite_invalid_signature", "invitation signature is invalid")
	}
	return nil
}

func codeFromInput(input string) (string, error) {
	value := strings.TrimSpace(input)
	if !strings.Contains(value, "://") {
		return value, nil
	}
	if !strings.HasPrefix(value, URLPrefix) {
		return "", fail("invite_malformed", "invalid invitation URL")
	}
	code := strings.TrimPrefix(value, URLPrefix)
	if code == "" || strings.ContainsAny(code, "/?#") {
		return "", fail("invite_malformed", "invalid invitation URL")
	}
	return code, nil
}

func normalizeNode(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("rendezvous node must be a plain HTTPS URL")
	}
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if parsed.Path == "" {
		parsed.Path = ""
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func scopesEqual(left, right []Scope) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return bytes.Equal(leftJSON, rightJSON)
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate object field %q", key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	return walk()
}
