// attest.go implements the local IPC attestation flow.
//
// Flow (design decision 2):
//
//  1. service requests challenge
//  2. agent issues nonce + agentKey
//  3. service signs nonce with its Ed25519 Hub identity key
//  4. service requests attestation, including signed nonce + local target
//  5. agent verifies: nonce freshness, signature valid under serviceKey,
//     target host is local (loopback or this machine)
//  6. agent issues short-lived AgentAttestation binding serviceKey, agentKey,
//     shareName, protocol, target — signed in the agent-attestation domain
//
// Local-target check rejects arbitrary remote hosts unless subnet routing is
// explicitly permitted (it is not in v1). See network-agent spec "Agent proves
// local publication".
package ipc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/v57/hub-service-go/identity"
	"github.com/v57/hub-service-go/protocol"
)

// ChallengeTTL bounds how long a nonce may be redeemed. Must stay short so a
// captured nonce cannot be replayed.
const ChallengeTTL = 30 * time.Second

// AttestationTTL bounds issued attestation validity. Hub re-checks the
// attestation signature on every share registration.
const AttestationTTL = 2 * time.Minute

// NonceLength is the random nonce byte length before base64 encoding.
const NonceLength = 24

// LocalTargetPolicy controls whether a target host is acceptable for
// attestation. v1 allows loopback and this-machine addresses only.
type LocalTargetPolicy struct {
	// AllowLoopback accepts 127.0.0.0/8, ::1, and "localhost".
	AllowLoopback bool
	// MachineAddresses are this machine's non-loopback interface addresses
	// (e.g. LAN IP). Targets equal to one of these are accepted.
	MachineAddresses []netip.Addr
	// AllowRemote is reserved for a future subnet-routing capability. v1
	// agents MUST leave it false; remote attestation is rejected.
	AllowRemote bool
}

// DefaultTargetPolicy returns a policy that allows loopback only. Production
// agents expand MachineAddresses from the local interface list.
func DefaultTargetPolicy() LocalTargetPolicy {
	return LocalTargetPolicy{AllowLoopback: true}
}

// IsLocalTarget reports whether host is acceptable under policy.
func IsLocalTarget(host string, policy LocalTargetPolicy) bool {
	if host == "localhost" {
		return policy.AllowLoopback
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if policy.AllowLoopback && (addr.IsLoopback() || addr.Is4In6()) {
		return true
	}
	for _, machine := range policy.MachineAddresses {
		if machine == addr {
			return true
		}
	}
	return policy.AllowRemote
}

// pendingChallenge tracks an unredeemed nonce plus the request that produced
// it, so /attest can be redeemed without the client echoing the nonce back
// (Bun, Swift, Go SDK clients all omit nonce from /attest). The pending map is
// keyed both by nonce (for direct redemption when the client does echo it) and
// by the composite pendingKey (for the common case).
type pendingChallenge struct {
	nonce      string
	serviceKey string
	shareName  string
	protocol   string
	target     protocol.LocalTarget
	expiresAt  time.Time
}

// AttestHandler is the production IPC Handler. It signs attestations with the
// agent's Hub identity, validates service proofs, and bounds nonce freshness.
type AttestHandler struct {
	mu        sync.Mutex
	agent     *identity.Identity
	agentKey  string
	policy    LocalTargetPolicy
	pending   map[string]pendingChallenge
	now       func() time.Time
	attestTTL time.Duration
}

// AttestHandlerOptions configures an AttestHandler.
type AttestHandlerOptions struct {
	Agent          *identity.Identity
	Policy         LocalTargetPolicy
	AttestationTTL time.Duration
	Now            func() time.Time
}

// NewAttestHandler constructs a handler. Agent identity is required because
// attestations are signed with the agent key (the same key Hub authenticated
// on the agent's Hub RPC connection).
func NewAttestHandler(options AttestHandlerOptions) (*AttestHandler, error) {
	if options.Agent == nil {
		return nil, errors.New("ipc: attest handler requires agent identity")
	}
	agentKey, err := options.Agent.PublicKeyBase64()
	if err != nil {
		return nil, fmt.Errorf("ipc: read agent public key: %w", err)
	}
	policy := options.Policy
	if !policy.AllowLoopback && len(policy.MachineAddresses) == 0 && !policy.AllowRemote {
		policy = DefaultTargetPolicy()
	}
	ttl := options.AttestationTTL
	if ttl == 0 {
		ttl = AttestationTTL
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &AttestHandler{
		agent:     options.Agent,
		agentKey:  agentKey,
		policy:    policy,
		pending:   make(map[string]pendingChallenge),
		now:       now,
		attestTTL: ttl,
	}, nil
}

// AgentKey returns the agent's SPKI base64 public key.
func (h *AttestHandler) AgentKey() string { return h.agentKey }

// SetNowForTest replaces the clock used for nonce/attestation expiry. Tests
// use it to advance time past the challenge TTL without sleeping.
func (h *AttestHandler) SetNowForTest(now func() time.Time) {
	h.mu.Lock()
	h.now = now
	h.mu.Unlock()
}

// Challenge issues a nonce bound to the requesting service key. If shareName,
// protocol, and target accompany the request (as the Bun, Swift, and Go SDK
// clients all send), the nonce is also keyed by that composite so the
// subsequent /attest call can be redeemed without echoing the nonce back.
func (h *AttestHandler) Challenge(req ChallengeRequest) (ChallengeResponse, error) {
	if req.ServiceKey == "" {
		return ChallengeResponse{}, errIPC("invalid_request", "serviceKey required")
	}
	if _, err := parseSPKIPublicKey(req.ServiceKey); err != nil {
		return ChallengeResponse{}, errIPC("invalid_request", "serviceKey not a valid SPKI ed25519 key")
	}
	nonce, err := randomNonce()
	if err != nil {
		return ChallengeResponse{}, errIPC("agent_unavailable", "nonce generation failed")
	}
	now := h.now()
	challenge := pendingChallenge{
		nonce:      nonce,
		serviceKey: req.ServiceKey,
		shareName:  req.ShareName,
		protocol:   req.Protocol,
		target:     req.Target,
		expiresAt:  now.Add(ChallengeTTL),
	}
	h.mu.Lock()
	// Drop any prior pending entry for the same nonce or composite so a
	// refreshed challenge supersedes a stale one.
	h.deleteLocked(nonce)
	if req.ShareName != "" && req.Protocol != "" && req.Target.Host != "" && req.Target.Port != 0 {
		h.deleteLocked(pendingKey(req.ServiceKey, req.ShareName, req.Protocol, req.Target))
	}
	h.pending[nonce] = challenge
	if req.ShareName != "" && req.Protocol != "" && req.Target.Host != "" && req.Target.Port != 0 {
		h.pending[pendingKey(req.ServiceKey, req.ShareName, req.Protocol, req.Target)] = challenge
	}
	h.pruneLocked(now)
	h.mu.Unlock()
	return ChallengeResponse{
		Version:   protocol.WireVersion,
		Type:      MessageAttestResponse,
		Nonce:     nonce,
		AgentKey:  h.agentKey,
		IssuedAt:  now,
		ExpiresAt: now.Add(ChallengeTTL),
	}, nil
}

// Attest verifies the service proof and issues a signed attestation.
//
// The pending challenge is redeemed by nonce when the client echoes it, else
// by the (serviceKey, shareName, protocol, target) composite — matching the
// Bun, Swift, and Go SDK clients, which omit nonce from /attest.
func (h *AttestHandler) Attest(req AttestRequest) (AttestResponse, error) {
	if req.ServiceKey == "" || req.ShareName == "" || req.Signature == "" {
		return AttestResponse{}, errIPC("invalid_request", "missing attestation fields")
	}
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		return AttestResponse{}, errIPC("invalid_request", "protocol must be tcp or udp")
	}
	if req.Target.Host == "" || req.Target.Port == 0 {
		return AttestResponse{}, errIPC("invalid_request", "target host and port required")
	}

	now := h.now()
	h.mu.Lock()
	var pending pendingChallenge
	var found bool
	if req.Nonce != "" {
		pending, found = h.pending[req.Nonce]
	}
	if !found {
		pending, found = h.pending[pendingKey(req.ServiceKey, req.ShareName, req.Protocol, req.Target)]
	}
	if !found || !now.Before(pending.expiresAt) {
		if req.Nonce != "" {
			h.deleteLocked(req.Nonce)
		}
		h.deleteLocked(pendingKey(req.ServiceKey, req.ShareName, req.Protocol, req.Target))
		h.pruneLocked(now)
		h.mu.Unlock()
		return AttestResponse{}, errIPC("invalid_nonce", "nonce unknown or expired")
	}
	// Drop both keys so the challenge is single-use.
	h.deleteLocked(pending.nonce)
	h.deleteLocked(pendingKey(pending.serviceKey, pending.shareName, pending.protocol, pending.target))
	h.pruneLocked(now)
	h.mu.Unlock()

	if pending.serviceKey != req.ServiceKey {
		return AttestResponse{}, errIPC("forbidden", "nonce bound to a different serviceKey")
	}

	publicKey, err := parseSPKIPublicKey(req.ServiceKey)
	if err != nil {
		return AttestResponse{}, errIPC("invalid_request", "serviceKey not a valid SPKI ed25519 key")
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return AttestResponse{}, errIPC("invalid_signature", "signature is not base64")
	}
	if !ed25519.Verify(publicKey, []byte(pending.nonce), signatureBytes) {
		return AttestResponse{}, errIPC("invalid_signature", "signature does not verify under serviceKey")
	}

	if !IsLocalTarget(req.Target.Host, h.policy) {
		return AttestResponse{}, errIPC("remote_target", "target is not a local address")
	}

	attestationID, err := randomID()
	if err != nil {
		return AttestResponse{}, errIPC("agent_unavailable", "attestation id generation failed")
	}
	issuedAt := now
	expiresAt := now.Add(h.attestTTL)
	attestation := protocol.AgentAttestation{
		Version:       protocol.WireVersion,
		AttestationID: attestationID,
		ServiceKey:    req.ServiceKey,
		AgentKey:      h.agentKey,
		ShareName:     req.ShareName,
		Protocol:      req.Protocol,
		Target:        req.Target,
		IssuedAt:      issuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:     expiresAt.UTC().Format(time.RFC3339Nano),
	}
	signature, err := protocol.SignEnvelope(protocol.PurposeAgentAttestation, attestation, h.agent.PrivateKey())
	if err != nil {
		return AttestResponse{}, fmt.Errorf("ipc: sign attestation: %w", err)
	}
	attestation.Signature = signature
	return AttestResponse{
		Version:     protocol.WireVersion,
		Type:        MessageAttestResponse,
		Attestation: attestation,
	}, nil
}

// Status reports agent readiness for IPC callers.
func (h *AttestHandler) Status(req StatusRequest) (StatusResponse, error) {
	now := h.now()
	h.mu.Lock()
	pending := len(h.pending)
	h.mu.Unlock()
	return StatusResponse{
		Version:    protocol.WireVersion,
		Type:       MessageStatusRequest,
		AgentKey:   h.agentKey,
		Ready:      true,
		ServerTime: now,
		Reason:     fmt.Sprintf("%d pending challenges", pending),
	}, nil
}

// pruneLocked drops expired challenges. Caller holds h.mu.
func (h *AttestHandler) pruneLocked(now time.Time) {
	for key, challenge := range h.pending {
		if !now.Before(challenge.expiresAt) {
			delete(h.pending, key)
		}
	}
}

// deleteLocked removes a key and, when the deleted entry corresponds to the
// same challenge, the companion key (nonce <-> composite) so the pending map
// never holds a dangling half. Caller holds h.mu.
func (h *AttestHandler) deleteLocked(key string) {
	challenge, ok := h.pending[key]
	if !ok {
		return
	}
	delete(h.pending, key)
	composite := pendingKey(challenge.serviceKey, challenge.shareName, challenge.protocol, challenge.target)
	if key != composite && key != challenge.nonce {
		return
	}
	if challenge.nonce != "" && challenge.nonce != key {
		if other, dup := h.pending[challenge.nonce]; dup && other == challenge {
			delete(h.pending, challenge.nonce)
		}
	}
	if composite != "" && composite != key {
		if other, dup := h.pending[composite]; dup && other == challenge {
			delete(h.pending, composite)
		}
	}
}

// pendingKey returns the composite key under which a challenge is redeemable
// without the client echoing the nonce. Empty shareName/protocol/host/port
// yield the empty string, signalling the request did not carry a full target
// (Challenge skips the composite entry in that case).
func pendingKey(serviceKey, shareName, protocol string, target protocol.LocalTarget) string {
	if serviceKey == "" || shareName == "" || protocol == "" || target.Host == "" || target.Port == 0 {
		return ""
	}
	return serviceKey + "|" + shareName + "|" + protocol + "|" + target.Host + "|" + strconv.Itoa(int(target.Port))
}

// randomNonce returns a base64-encoded random nonce.
func randomNonce() (string, error) {
	buf := make([]byte, NonceLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// randomID returns a short opaque attestation identifier.
func randomID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "att-" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// parseSPKIPublicKey decodes a base64 SPKI Ed25519 public key.
func parseSPKIPublicKey(b64 string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return ed, nil
}

// ipcError carries a wire-level error code so callers can surface it to the
// requesting service. Implements the error interface.
type ipcError struct {
	code string
	msg  string
}

func errIPC(code, msg string) error {
	return &ipcError{code: code, msg: msg}
}

func (e *ipcError) Error() string { return fmt.Sprintf("%s: %s", e.code, e.msg) }

// Code returns the wire-level error code.
func (e *ipcError) Code() string { return e.code }
