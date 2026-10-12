// Package invitation validates compact agent-signed Hub Network invitations.
package invitation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
	"time"
)

const URLPrefix = "hub://join/"
const DefaultNode = "https://hub.v57.dev/node"
const MaxLifetime = 8 * 24 * time.Hour
const MaxCodeSize = 1024

var spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

type Envelope struct {
	TokenID     string
	ExpiresAt   string
	InvitingKey string
	Signature   string
}
type Decoded struct {
	Envelope                 Envelope
	Node, Code, URL, Payload string
	Nonce, Expires           uint32
}
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string        { return e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error        { return e.Err }
func fail(code, message string) error { return &Error{Code: code, Err: errors.New(message)} }

func Decode(input string, now time.Time) (Decoded, error) {
	code := strings.TrimSpace(input)
	if strings.HasPrefix(code, URLPrefix) {
		code = strings.TrimPrefix(code, URLPrefix)
	} else if strings.Contains(code, "://") {
		return Decoded{}, fail("invite_malformed", "invalid invitation URL")
	}
	if code == "" || len(code) > MaxCodeSize {
		return Decoded{}, fail("invite_malformed", "invitation size is invalid")
	}
	slash := strings.LastIndexByte(code, '/')
	if slash <= 0 || slash == len(code)-1 {
		return Decoded{}, fail("invite_malformed", "invalid invitation format")
	}
	payload, signaturePart := code[:slash], code[slash+1:]
	base, rawQuery, _ := strings.Cut(payload, "?")
	parts := strings.Split(base, ".")
	if len(parts) != 3 {
		return Decoded{}, fail("invite_unsupported_version", "unsupported invitation version")
	}
	agent, err := decodePart(parts[0], 32)
	if err != nil {
		return Decoded{}, fail("invite_malformed", "invalid agent key")
	}
	expiresBytes, err := decodePart(parts[1], 4)
	if err != nil {
		return Decoded{}, fail("invite_malformed", "invalid expiration")
	}
	nonceBytes, err := decodePart(parts[2], 4)
	if err != nil {
		return Decoded{}, fail("invite_malformed", "invalid nonce")
	}
	signature, err := decodePart(signaturePart, 64)
	if err != nil {
		return Decoded{}, fail("invite_malformed", "invalid signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(agent), []byte(payload), signature) {
		return Decoded{}, fail("invite_invalid_signature", "invitation signature is invalid")
	}
	expires := binary.BigEndian.Uint32(expiresBytes)
	expiration := time.Unix(int64(expires), 0).UTC()
	if !expiration.After(now) {
		return Decoded{}, fail("invite_expired", "invitation has expired")
	}
	if expiration.After(now.Add(MaxLifetime)) {
		return Decoded{}, fail("invite_invalid_time", "invitation exceeds maximum lifetime")
	}
	node := DefaultNode
	if rawQuery != "" {
		query, err := url.ParseQuery(rawQuery)
		if err != nil || len(query) != 1 || len(query["e"]) != 1 || query.Encode() != rawQuery || query.Get("e") == "" {
			return Decoded{}, fail("invite_non_canonical", "invalid invitation query")
		}
		endpoint := query.Get("e")
		if strings.Contains(endpoint, "://") {
			node = endpoint
		} else {
			node = "https://" + endpoint
		}
	}
	digest := sha256.Sum256([]byte(payload))
	spki := append(append([]byte{}, spkiPrefix...), agent...)
	return Decoded{Envelope: Envelope{TokenID: base64.RawURLEncoding.EncodeToString(digest[:]), ExpiresAt: expiration.Format(time.RFC3339), InvitingKey: base64.StdEncoding.EncodeToString(spki), Signature: signaturePart}, Node: node, Code: code, URL: URLPrefix + code, Payload: payload, Nonce: binary.BigEndian.Uint32(nonceBytes), Expires: expires}, nil
}
func decodePart(value string, size int) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, errors.New("non-canonical base64url")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical base64url")
	}
	return decoded, nil
}
