// Direct bootstrap exchange.
//
// A compact invitation only carries the inviter's service key, expiry, and a
// nonce. After the hub-net-node pairs a joiner with the online inviter, the
// two authenticate directly: the joiner signs a DirectBootstrapRequest with
// its service key, and the inviter answers with a DirectBootstrapResponse
// signed by the invitation service key (the same key that signed the compact
// invitation). The response binds to the invitation replay id and the joiner
// identities, and carries the temporary point-to-point WireGuard addresses
// the joiner needs to reach hub-pro through the inviter before its ordinary
// hub/net/bind assigns permanent overlay addresses.
//
// The wire structs are shared cross-language in hub-service-go/protocol (and
// the Swift mirror in HubService) and sign as canonical envelopes under the
// hub-network/direct-bootstrap-request|response/v1 domains. This package owns
// the inviter side: request verification, temporary peer installation, and
// cleanup. The joiner-side client (Go and Apple) consumes VerifyInviterResponse
// and the signed response.
package invitation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/v57/hub-net/wireguard"
	"github.com/v57/hub-service-go/identity"
	"github.com/v57/hub-service-go/protocol"
)

// Bootstrap address pools. The old Apple flow used addresses inside the
// reserved infrastructure ranges (100.127.255.0/24 and
// fd48:5542:4e45:ffff::/64); the current adapter refuses routes overlapping
// those reserved ranges, so temporary bootstrap links use adjacent overlay
// ranges that are still inside the frozen overlay prefixes and collision-free
// per session.
var (
	bootstrapIPv4Pool = netip.MustParsePrefix("100.127.254.0/24")
	bootstrapIPv6Pool = netip.MustParsePrefix("fd48:5542:4e45:fffe::/64")
)

// bootstrapVersion is the current direct bootstrap wire version.
const bootstrapVersion = 1

// Errors returned by the inviter handler. Callers map these to wire-shaped
// network errors.
var (
	ErrBootstrapRequest  = errors.New("invitation: invalid bootstrap request")
	ErrBootstrapResponse = errors.New("invitation: invalid bootstrap response")
	ErrBootstrapReplay   = errors.New("invitation: bootstrap request already used")
	ErrBootstrapCapacity = errors.New("invitation: bootstrap address capacity exceeded")
)

func bootstrapFail(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBootstrapRequest, fmt.Sprintf(format, args...))
}

func responseFail(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBootstrapResponse, fmt.Sprintf(format, args...))
}

// decodeServiceKey validates a canonical Ed25519 SPKI base64 service key and
// returns the raw public key. Service keys in Hub Network APIs are always the
// canonical SPKI form; raw 32-byte keys are rejected at API boundaries.
func decodeServiceKey(encoded string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("service key is not base64")
	}
	if len(der) != len(spkiPrefix)+ed25519.PublicKeySize {
		return nil, errors.New("service key has invalid length")
	}
	if !slices.Equal(der[:len(spkiPrefix)], spkiPrefix) {
		return nil, errors.New("service key is not an Ed25519 SPKI")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("service key is not a valid SPKI")
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("service key is not Ed25519")
	}
	return publicKey, nil
}

// decodeWireGuardKey validates a 32-byte Curve25519 public key in base64.
func decodeWireGuardKey(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("wireguard key is not base64")
	}
	if len(raw) != 32 {
		return nil, errors.New("wireguard key must be 32 bytes")
	}
	return raw, nil
}

// validateReplayID checks the invitation replay id: SHA-256 of the exact
// compact invitation payload, unpadded Base64URL. This is the same digest the
// hub-net-node uses for its in-memory used set.
func validateReplayID(replayID string) error {
	raw, err := base64.RawURLEncoding.DecodeString(replayID)
	if err != nil || len(raw) != sha256.Size {
		return errors.New("replay id must be unpadded base64url SHA-256")
	}
	return nil
}

// SignJoinerRequest fills version, signature domain, and the Ed25519 signature
// on a joiner bootstrap request. privateKey is the joiner's service key, the
// same key that authenticates the joiner's hub/net/bind.
func SignJoinerRequest(request *protocol.DirectBootstrapRequest, privateKey ed25519.PrivateKey) error {
	if request == nil {
		return errors.New("invitation: nil bootstrap request")
	}
	domain, err := protocol.DomainFor(protocol.PurposeDirectBootstrapRequest)
	if err != nil {
		return err
	}
	request.Version = bootstrapVersion
	request.SignatureDomain = domain
	signature, err := protocol.SignEnvelope(protocol.PurposeDirectBootstrapRequest, *request, privateKey)
	if err != nil {
		return fmt.Errorf("invitation: sign bootstrap request: %w", err)
	}
	request.Signature = signature
	return nil
}

// VerifyJoinerRequest validates a joiner bootstrap request and authenticates
// it: the signature must verify under the request's service key, so a joiner
// proves possession of the identity it asserts.
func VerifyJoinerRequest(request protocol.DirectBootstrapRequest, now time.Time) error {
	if request.Version != bootstrapVersion {
		return bootstrapFail("unsupported version %d", request.Version)
	}
	domain, err := protocol.DomainFor(protocol.PurposeDirectBootstrapRequest)
	if err != nil {
		return err
	}
	if request.SignatureDomain != domain {
		return bootstrapFail("unexpected signature domain %q", request.SignatureDomain)
	}
	if err := validateReplayID(request.ReplayID); err != nil {
		return bootstrapFail("%v", err)
	}
	joinerKey, err := decodeServiceKey(request.JoinerServiceKey)
	if err != nil {
		return bootstrapFail("joiner %v", err)
	}
	if _, err := decodeWireGuardKey(request.JoinerWireGuardKey); err != nil {
		return bootstrapFail("joiner %v", err)
	}
	if request.Nonce == "" || len(request.Nonce) > 128 {
		return bootstrapFail("invalid nonce")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, request.IssuedAt)
	if err != nil {
		return bootstrapFail("invalid issuedAt")
	}
	if issuedAt.After(now.Add(protocol.MaxClockSkew)) || issuedAt.Before(now.Add(-protocol.MaxClockSkew)) {
		return bootstrapFail("issuedAt outside clock skew")
	}
	valid, err := protocol.VerifyEnvelope(protocol.PurposeDirectBootstrapRequest, request, joinerKey, request.Signature)
	if err != nil {
		return bootstrapFail("signature check failed")
	}
	if !valid {
		return bootstrapFail("joiner signature invalid")
	}
	return nil
}

// VerifyInviterResponse validates and authenticates an inviter bootstrap
// response against the request that produced it. The signature must verify
// under the invitation service key (the key that signed the compact
// invitation), and every identity field must bind to the request.
func VerifyInviterResponse(response protocol.DirectBootstrapResponse, request protocol.DirectBootstrapRequest, now time.Time) error {
	if response.Version != bootstrapVersion {
		return responseFail("unsupported version %d", response.Version)
	}
	domain, err := protocol.DomainFor(protocol.PurposeDirectBootstrapResponse)
	if err != nil {
		return err
	}
	if response.SignatureDomain != domain {
		return responseFail("unexpected signature domain %q", response.SignatureDomain)
	}
	if response.ReplayID != request.ReplayID {
		return responseFail("response not bound to request replay id")
	}
	if response.JoinerServiceKey != request.JoinerServiceKey ||
		response.JoinerWireGuardKey != request.JoinerWireGuardKey {
		return responseFail("response bound to different joiner")
	}
	inviterKey, err := decodeServiceKey(response.InviterServiceKey)
	if err != nil {
		return responseFail("inviter %v", err)
	}
	if _, err := decodeWireGuardKey(response.InviterWireGuardKey); err != nil {
		return responseFail("inviter %v", err)
	}
	if len(response.Endpoints) == 0 {
		return responseFail("no endpoints")
	}
	for _, endpoint := range response.Endpoints {
		if endpoint.Transport != "udp" {
			return responseFail("endpoint transport must be udp")
		}
		address, err := netip.ParseAddr(endpoint.Address)
		if err != nil || endpoint.Port == 0 {
			return responseFail("invalid endpoint")
		}
		_ = address
	}
	joinerV4, joinerV6, err := parseBootstrapAddress(response.JoinerAddress)
	if err != nil {
		return responseFail("joiner %v", err)
	}
	inviterV4, inviterV6, err := parseBootstrapAddress(response.InviterAddress)
	if err != nil {
		return responseFail("inviter %v", err)
	}
	if joinerV4 == inviterV4 || joinerV6 == inviterV6 {
		return responseFail("joiner and inviter addresses collide")
	}
	hubProHost, err := netip.ParseAddr(response.HubProHost)
	if err != nil {
		return responseFail("invalid hubProHost")
	}
	_ = hubProHost
	issuedAt, err := time.Parse(time.RFC3339Nano, response.IssuedAt)
	if err != nil {
		return responseFail("invalid issuedAt")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, response.ExpiresAt)
	if err != nil {
		return responseFail("invalid expiresAt")
	}
	if expiresAt.Before(issuedAt) {
		return responseFail("expiresAt before issuedAt")
	}
	if expiresAt.Sub(issuedAt) > protocol.DirectBootstrapMaxLifetime {
		return responseFail("response lifetime exceeds maximum")
	}
	if issuedAt.After(now.Add(protocol.MaxClockSkew)) || issuedAt.Before(now.Add(-protocol.MaxClockSkew)) {
		return responseFail("issuedAt outside clock skew")
	}
	if !expiresAt.After(now) {
		return responseFail("response expired")
	}
	valid, err := protocol.VerifyEnvelope(protocol.PurposeDirectBootstrapResponse, response, inviterKey, response.Signature)
	if err != nil {
		return responseFail("signature check failed")
	}
	if !valid {
		return responseFail("inviter signature invalid")
	}
	return nil
}

func parseBootstrapAddress(address protocol.BootstrapAddress) (netip.Addr, netip.Addr, error) {
	v4, err := netip.ParseAddr(address.IPv4)
	if err != nil || !v4.Is4() {
		return netip.Addr{}, netip.Addr{}, errors.New("invalid ipv4")
	}
	v6, err := netip.ParseAddr(address.IPv6)
	if err != nil || !v6.Is6() {
		return netip.Addr{}, netip.Addr{}, errors.New("invalid ipv6")
	}
	return v4, v6, nil
}

// tempPeer is one live temporary bootstrap link on the inviter.
type tempPeer struct {
	replayID        string
	joinerService   string
	joinerWireGuard []byte
	request         protocol.DirectBootstrapRequest
	response        protocol.DirectBootstrapResponse
	joinerV4        netip.Addr
	joinerV6        netip.Addr
	expiresAt       time.Time
}

// Inviter handles signed joiner bootstrap requests: it verifies the joiner,
// installs a temporary WireGuard peer for the assigned point-to-point
// addresses, and answers with a response signed by the invitation service
// key. Temporary peers are removed when their response expires (Sweep) or on
// explicit close.
type Inviter struct {
	identity    *identity.Identity
	wgPublicKey []byte
	adapter     wireguard.Adapter
	endpoints   func() []protocol.BootstrapEndpoint
	hubProHost  func() string
	lifetime    time.Duration
	now         func() time.Time
	memberPeer  func(wireGuardKey []byte) []netip.Prefix

	mu        sync.Mutex
	active    map[string]*tempPeer
	allocator *addressAllocator
}

// InviterOptions configures the inviter bootstrap handler.
type InviterOptions struct {
	// Identity is the invitation service identity. It must be the same key
	// that signs compact invitations; responses verify under its public key.
	Identity *identity.Identity
	// WireGuardKey is the inviter's 32-byte Curve25519 public key, advertised
	// to joiners as the temporary peer key.
	WireGuardKey []byte
	// Adapter installs and removes the temporary joiner peer.
	Adapter wireguard.Adapter
	// Endpoints returns the inviter's reachable WireGuard UDP endpoints.
	// May be nil or return nil; responses then carry no endpoints and joiners
	// must rely on node-observed candidates.
	Endpoints func() []protocol.BootstrapEndpoint
	// HubProHost returns the inviter's overlay address where hub-pro listens
	// on :1997. May be nil.
	HubProHost func() string
	// Lifetime bounds a bootstrap response. Defaults to
	// protocol.DirectBootstrapMaxLifetime.
	Lifetime time.Duration
	// Now is the clock; tests inject a controllable time.
	Now func() time.Time
	// MemberPeer returns the permanent overlay addresses of a network member
	// with this WireGuard key, or nil. Closing a temporary peer of a member
	// keeps the member's peer with those addresses instead of removing it.
	MemberPeer func(wireGuardKey []byte) []netip.Prefix
}

// NewInviter constructs the inviter bootstrap handler.
func NewInviter(options InviterOptions) (*Inviter, error) {
	if options.Identity == nil {
		return nil, errors.New("invitation: inviter identity required")
	}
	if len(options.WireGuardKey) != 32 {
		return nil, errors.New("invitation: inviter wireguard key must be 32 bytes")
	}
	if options.Adapter == nil {
		return nil, errors.New("invitation: inviter adapter required")
	}
	lifetime := options.Lifetime
	if lifetime <= 0 {
		lifetime = protocol.DirectBootstrapMaxLifetime
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Inviter{
		identity:    options.Identity,
		wgPublicKey: append([]byte(nil), options.WireGuardKey...),
		adapter:     options.Adapter,
		endpoints:   options.Endpoints,
		hubProHost:  options.HubProHost,
		lifetime:    lifetime,
		now:         now,
		memberPeer:  options.MemberPeer,
		active:      make(map[string]*tempPeer),
		allocator:   newAddressAllocator(),
	}, nil
}

// Handle verifies one joiner bootstrap request, installs the temporary peer,
// and returns the signed inviter response. Repeating the identical request
// returns the same response (transport retries); a different request for the
// same invitation replay id is rejected.
func (i *Inviter) Handle(ctx context.Context, request protocol.DirectBootstrapRequest) (protocol.DirectBootstrapResponse, error) {
	if err := VerifyJoinerRequest(request, i.now()); err != nil {
		return protocol.DirectBootstrapResponse{}, err
	}
	joinerWireGuard, err := decodeWireGuardKey(request.JoinerWireGuardKey)
	if err != nil {
		return protocol.DirectBootstrapResponse{}, err
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	replayKey := request.ReplayID
	if existing, ok := i.active[replayKey]; ok {
		if i.now().Before(existing.expiresAt) {
			if existing.joinerService == request.JoinerServiceKey &&
				existing.request.Nonce == request.Nonce {
				return existing.response, nil
			}
			return protocol.DirectBootstrapResponse{}, fmt.Errorf("%w: invitation already in use", ErrBootstrapReplay)
		}
		i.closeLocked(ctx, existing)
	}

	joinerV4, joinerV6, err := i.allocator.allocate()
	if err != nil {
		return protocol.DirectBootstrapResponse{}, err
	}
	install := func() error {
		return i.adapter.AddPeer(wireguard.PeerConfig{
			PublicKey: joinerWireGuard,
			AllowedIPs: []netip.Prefix{
				netip.PrefixFrom(joinerV4, 32),
				netip.PrefixFrom(joinerV6, 128),
			},
		})
	}
	if err := install(); err != nil {
		i.allocator.release(joinerV4, joinerV6)
		return protocol.DirectBootstrapResponse{}, fmt.Errorf("invitation: install temporary peer: %w", err)
	}

	response, err := i.buildResponse(request, joinerV4, joinerV6)
	if err != nil {
		_ = i.adapter.RemovePeer(joinerWireGuard)
		i.allocator.release(joinerV4, joinerV6)
		return protocol.DirectBootstrapResponse{}, err
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, response.ExpiresAt)
	i.active[replayKey] = &tempPeer{
		replayID:        replayKey,
		joinerService:   request.JoinerServiceKey,
		joinerWireGuard: joinerWireGuard,
		request:         request,
		response:        response,
		joinerV4:        joinerV4,
		joinerV6:        joinerV6,
		expiresAt:       expiresAt,
	}
	return response, nil
}

func (i *Inviter) buildResponse(request protocol.DirectBootstrapRequest, joinerV4, joinerV6 netip.Addr) (protocol.DirectBootstrapResponse, error) {
	inviterKey, err := i.identity.PublicKeyBase64()
	if err != nil {
		return protocol.DirectBootstrapResponse{}, err
	}
	inviterV4 := i.allocator.inviterV4()
	inviterV6 := i.allocator.inviterV6()
	now := i.now().UTC()
	expires := now.Add(i.lifetime)
	var endpoints []protocol.BootstrapEndpoint
	if i.endpoints != nil {
		endpoints = append(endpoints, i.endpoints()...)
	}
	var hubProHost string
	if i.hubProHost != nil {
		hubProHost = i.hubProHost()
	}
	if hubProHost == "" {
		return protocol.DirectBootstrapResponse{}, errors.New("invitation: hubProHost unavailable")
	}
	response := protocol.DirectBootstrapResponse{
		Version:             bootstrapVersion,
		ReplayID:            request.ReplayID,
		InviterServiceKey:   inviterKey,
		JoinerServiceKey:    request.JoinerServiceKey,
		JoinerWireGuardKey:  request.JoinerWireGuardKey,
		InviterWireGuardKey: base64.StdEncoding.EncodeToString(i.wgPublicKey),
		Endpoints:           endpoints,
		JoinerAddress: protocol.BootstrapAddress{
			IPv4: joinerV4.String(), IPv6: joinerV6.String(),
		},
		InviterAddress: protocol.BootstrapAddress{
			IPv4: inviterV4.String(), IPv6: inviterV6.String(),
		},
		HubProHost: hubProHost,
		IssuedAt:   now.Format(time.RFC3339Nano),
		ExpiresAt:  expires.Format(time.RFC3339Nano),
	}
	domain, err := protocol.DomainFor(protocol.PurposeDirectBootstrapResponse)
	if err != nil {
		return protocol.DirectBootstrapResponse{}, err
	}
	response.SignatureDomain = domain
	signature, err := protocol.SignEnvelope(protocol.PurposeDirectBootstrapResponse, response, i.identity.PrivateKey())
	if err != nil {
		return protocol.DirectBootstrapResponse{}, err
	}
	response.Signature = signature
	return response, nil
}

// UpdateJoinerAllowedIPs extends every active temporary peer for
// joinerServiceKey with additional overlay addresses — the joiner's permanent
// hub-pro-assigned addresses after its hub/net/bind. The bootstrap addresses
// remain; the adapter replaces the peer's AllowedIPs with the union so the
// inviter keeps forwarding the joiner's adopted control traffic. Returns
// ErrBootstrapReplay when no active peer matches the service key.
func (i *Inviter) UpdateJoinerAllowedIPs(ctx context.Context, joinerServiceKey string, extra []netip.Prefix) error {
	if joinerServiceKey == "" || len(extra) == 0 {
		return errors.New("invitation: inviter peer update requires service key and addresses")
	}
	for _, prefix := range extra {
		if err := wireguard.ValidateAllowedIPs([]netip.Prefix{prefix}); err != nil {
			return fmt.Errorf("invitation: inviter peer update: %w", err)
		}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	updated := false
	for _, peer := range i.active {
		if peer.joinerService != joinerServiceKey {
			continue
		}
		allowed := []netip.Prefix{
			netip.PrefixFrom(peer.joinerV4, 32),
			netip.PrefixFrom(peer.joinerV6, 128),
		}
		for _, prefix := range extra {
			if !slices.Contains(allowed, prefix) {
				allowed = append(allowed, prefix)
			}
		}
		if err := i.adapter.AddPeer(wireguard.PeerConfig{
			PublicKey:  peer.joinerWireGuard,
			AllowedIPs: allowed,
		}); err != nil {
			return fmt.Errorf("invitation: update joiner peer: %w", err)
		}
		updated = true
	}
	if !updated {
		return fmt.Errorf("%w: no active bootstrap peer for joiner", ErrBootstrapReplay)
	}
	return nil
}

// CloseJoiner removes the temporary peer for one invitation replay id and
// releases its addresses. Idempotent.
func (i *Inviter) CloseJoiner(ctx context.Context, replayID string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	peer, ok := i.active[replayID]
	if !ok {
		return nil
	}
	i.closeLocked(ctx, peer)
	return nil
}

// Sweep closes every temporary peer whose response has expired.
func (i *Inviter) Sweep(ctx context.Context) {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.now()
	for replayID, peer := range i.active {
		if !now.Before(peer.expiresAt) {
			i.closeLocked(ctx, peer)
			delete(i.active, replayID)
		}
	}
}

// CloseAll removes every temporary peer. Called on agent shutdown.
func (i *Inviter) CloseAll(ctx context.Context) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for replayID, peer := range i.active {
		i.closeLocked(ctx, peer)
		delete(i.active, replayID)
	}
}

func (i *Inviter) closeLocked(ctx context.Context, peer *tempPeer) {
	if i.memberPeer != nil {
		if allowed := i.memberPeer(peer.joinerWireGuard); len(allowed) > 0 {
			// The joiner became a member: drop only the bootstrap addresses.
			_ = i.adapter.AddPeer(wireguard.PeerConfig{PublicKey: peer.joinerWireGuard, AllowedIPs: allowed})
		} else {
			_ = i.adapter.RemovePeer(peer.joinerWireGuard)
		}
	} else {
		_ = i.adapter.RemovePeer(peer.joinerWireGuard)
	}
	i.allocator.release(peer.joinerV4, peer.joinerV6)
	delete(i.active, peer.replayID)
	_ = ctx
}

// Active reports the number of live temporary bootstrap peers. Exposed for
// diagnostics and tests.
func (i *Inviter) Active() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.active)
}

// addressAllocator hands out unique temporary point-to-point addresses from
// the bootstrap pools. The inviter address is fixed (the inviter's local side
// of every bootstrap link); each joiner gets a unique pair.
type addressAllocator struct {
	mu   sync.Mutex
	next uint32
	used map[string]bool
}

func newAddressAllocator() *addressAllocator {
	return &addressAllocator{next: 2, used: make(map[string]bool)}
}

func (a *addressAllocator) inviterV4() netip.Addr {
	return bootstrapIPv4Pool.Addr().Next()
}

func (a *addressAllocator) inviterV6() netip.Addr {
	return bootstrapIPv6Pool.Addr().Next()
}

func (a *addressAllocator) allocate() (netip.Addr, netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	base := bootstrapIPv4Pool.Addr()
	for i := a.next; ; i++ {
		if int(i) >= 255 {
			return netip.Addr{}, netip.Addr{}, ErrBootstrapCapacity
		}
		candidate := netip.AddrFrom4([4]byte{base.As4()[0], base.As4()[1], base.As4()[2], byte(i)})
		if !a.used[candidate.String()] {
			a.next = i + 1
			a.used[candidate.String()] = true
			v6 := bootstrapIPv6Pool.Addr()
			v6Bytes := v6.As16()
			v6Bytes[14] = byte(i >> 8)
			v6Bytes[15] = byte(i)
			v6Candidate := netip.AddrFrom16(v6Bytes)
			a.used[v6Candidate.String()] = true
			return candidate, v6Candidate, nil
		}
	}
}

func (a *addressAllocator) release(joinerV4, joinerV6 netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.used, joinerV4.String())
	delete(a.used, joinerV6.String())
}
