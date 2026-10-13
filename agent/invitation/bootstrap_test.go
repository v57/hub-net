package invitation

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/v57/hub-net-node/identity"
	protocol "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net/wireguard"
)

func wgKeyPair(t *testing.T) (private, public []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key.Bytes(), key.PublicKey().Bytes()
}

func validReplayID(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// signalled records the node's signal for request, as the agent does when the
// node pushes inviter.bootstrap.
func signalled(inviter *Inviter, request protocol.DirectBootstrapRequest) protocol.DirectBootstrapRequest {
	inviter.Expect(request.ReplayID, request.JoinerServiceKey)
	return request
}

func newBootstrapRequest(t *testing.T, joiner *identity.Identity, wgKey []byte, replayID, nonce string, issuedAt time.Time) protocol.DirectBootstrapRequest {
	t.Helper()
	serviceKey, err := joiner.PublicKeyBase64()
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.DirectBootstrapRequest{
		Version:            bootstrapVersion,
		ReplayID:           replayID,
		JoinerServiceKey:   serviceKey,
		JoinerWireGuardKey: base64.StdEncoding.EncodeToString(wgKey),
		Nonce:              nonce,
		IssuedAt:           issuedAt.UTC().Format(time.RFC3339Nano),
	}
	if err := SignJoinerRequest(&request, joiner.PrivateKey()); err != nil {
		t.Fatal(err)
	}
	return request
}

// testInviter builds an inviter with a FakeAdapter and a mutable clock. The
// returned *time.Time is read through the clock closure, so tests advance it
// by mutation.
func testInviter(t *testing.T, clock *time.Time) (*Inviter, *identity.Identity, []byte, *wireguard.FakeAdapter) {
	t.Helper()
	inviterID, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, wgPublic := wgKeyPair(t)
	adapter := wireguard.NewFakeAdapter()
	if err := adapter.Up(wireguard.InterfaceConfig{
		Name:       "hubnet0",
		PrivateKey: make([]byte, 32),
		Address:    netip.MustParseAddr("100.96.0.1"),
		ListenPort: 51820,
	}); err != nil {
		t.Fatal(err)
	}
	options := InviterOptions{
		Identity:     inviterID,
		WireGuardKey: wgPublic,
		Adapter:      adapter,
		Endpoints: func() []protocol.BootstrapEndpoint {
			return []protocol.BootstrapEndpoint{{Address: "203.0.113.10", Port: 51820, Transport: "udp"}}
		},
		HubProHost: func() string { return "100.96.0.1" },
	}
	if clock != nil {
		options.Now = func() time.Time { return *clock }
	}
	inviter, err := NewInviter(options)
	if err != nil {
		t.Fatal(err)
	}
	return inviter, inviterID, wgPublic, adapter
}

func TestInviterRoundTrip(t *testing.T) {
	now := time.Now()
	inviter, inviterID, inviterWG, adapter := testInviter(t, &now)
	joiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, joinerWG := wgKeyPair(t)
	replayID := validReplayID(t)
	request := signalled(inviter, newBootstrapRequest(t, joiner, joinerWG, replayID, "nonce-1", now))

	response, err := inviter.Handle(context.Background(), request)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if err := VerifyInviterResponse(response, request, now); err != nil {
		t.Fatalf("VerifyInviterResponse: %v", err)
	}
	if response.ReplayID != replayID {
		t.Fatalf("response replay id = %q, want %q", response.ReplayID, replayID)
	}
	if response.JoinerServiceKey != request.JoinerServiceKey ||
		response.JoinerWireGuardKey != request.JoinerWireGuardKey {
		t.Fatal("response not bound to joiner")
	}
	inviterServiceKey, err := inviterID.PublicKeyBase64()
	if err != nil {
		t.Fatal(err)
	}
	if response.InviterServiceKey != inviterServiceKey {
		t.Fatal("response inviter service key mismatch")
	}
	if got, _ := base64.StdEncoding.DecodeString(response.InviterWireGuardKey); !slices.Equal(got, inviterWG) {
		t.Fatal("response inviter wireguard key mismatch")
	}
	joinerV4 := netip.MustParseAddr(response.JoinerAddress.IPv4)
	joinerV6 := netip.MustParseAddr(response.JoinerAddress.IPv6)
	if !bootstrapIPv4Pool.Contains(joinerV4) || !bootstrapIPv6Pool.Contains(joinerV6) {
		t.Fatalf("joiner addresses outside bootstrap pools: %s %s", joinerV4, joinerV6)
	}
	if response.HubProHost != "100.96.0.1" || len(response.Endpoints) != 1 {
		t.Fatal("response missing hubProHost or endpoints")
	}
	issuedAt, _ := time.Parse(time.RFC3339Nano, response.IssuedAt)
	expiresAt, _ := time.Parse(time.RFC3339Nano, response.ExpiresAt)
	if expiresAt.Sub(issuedAt) != protocol.DirectBootstrapMaxLifetime {
		t.Fatalf("response lifetime = %v, want %v", expiresAt.Sub(issuedAt), protocol.DirectBootstrapMaxLifetime)
	}

	// Temporary peer installed with both point-to-point addresses allowed.
	state, up := adapter.State()
	if !up {
		t.Fatal("adapter not up")
	}
	var peer *wireguard.PeerConfig
	for index := range state.Peers {
		if slices.Equal(state.Peers[index].PublicKey, joinerWG) {
			peer = &state.Peers[index]
			break
		}
	}
	if peer == nil {
		t.Fatal("temporary joiner peer not installed")
	}
	wantIPs := []netip.Prefix{
		netip.PrefixFrom(joinerV4, 32),
		netip.PrefixFrom(joinerV6, 128),
	}
	if !slices.Equal(peer.AllowedIPs, wantIPs) {
		t.Fatalf("peer allowed IPs = %v, want %v", peer.AllowedIPs, wantIPs)
	}

	if err := inviter.CloseJoiner(context.Background(), replayID); err != nil {
		t.Fatalf("CloseJoiner: %v", err)
	}
	state, _ = adapter.State()
	for _, existing := range state.Peers {
		if slices.Equal(existing.PublicKey, joinerWG) {
			t.Fatal("temporary peer still installed after CloseJoiner")
		}
	}
	if inviter.Active() != 0 {
		t.Fatalf("active = %d, want 0", inviter.Active())
	}
}

func TestVerifyJoinerRequestRejects(t *testing.T) {
	now := time.Now()
	joiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, joinerWG := wgKeyPair(t)
	replayID := validReplayID(t)
	base := newBootstrapRequest(t, joiner, joinerWG, replayID, "nonce-1", now)

	other, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	rawKey := other.PublicKey()
	rawKeyBase64 := base64.StdEncoding.EncodeToString(rawKey)

	tests := []struct {
		name    string
		mutate  func(*protocol.DirectBootstrapRequest)
		wantErr error
	}{
		{"unsupported version", func(r *protocol.DirectBootstrapRequest) { r.Version = 2 }, ErrBootstrapRequest},
		{"wrong domain", func(r *protocol.DirectBootstrapRequest) {
			r.SignatureDomain = "hub-network/direct-bootstrap-response/v1"
		}, ErrBootstrapRequest},
		{"short replay id", func(r *protocol.DirectBootstrapRequest) {
			r.ReplayID = base64.RawURLEncoding.EncodeToString([]byte("short"))
		}, ErrBootstrapRequest},
		{"raw key not spki", func(r *protocol.DirectBootstrapRequest) {
			r.JoinerServiceKey = rawKeyBase64
		}, ErrBootstrapRequest},
		{"garbage service key", func(r *protocol.DirectBootstrapRequest) {
			r.JoinerServiceKey = "not-a-key"
		}, ErrBootstrapRequest},
		{"short wireguard key", func(r *protocol.DirectBootstrapRequest) {
			r.JoinerWireGuardKey = base64.StdEncoding.EncodeToString([]byte("short"))
		}, ErrBootstrapRequest},
		{"empty nonce", func(r *protocol.DirectBootstrapRequest) { r.Nonce = "" }, ErrBootstrapRequest},
		{"future issuedAt", func(r *protocol.DirectBootstrapRequest) {
			r.IssuedAt = now.Add(2 * protocol.MaxClockSkew).Format(time.RFC3339Nano)
		}, ErrBootstrapRequest},
		{"stale issuedAt", func(r *protocol.DirectBootstrapRequest) {
			r.IssuedAt = now.Add(-2 * protocol.MaxClockSkew).Format(time.RFC3339Nano)
		}, ErrBootstrapRequest},
		{"tampered fields", func(r *protocol.DirectBootstrapRequest) {
			r.Nonce = "tampered"
		}, ErrBootstrapRequest},
		{"signature by different key", func(r *protocol.DirectBootstrapRequest) {
			signature, signErr := protocol.SignEnvelope(protocol.PurposeDirectBootstrapRequest, *r, other.PrivateKey())
			if signErr != nil {
				t.Fatal(signErr)
			}
			r.Signature = signature
		}, ErrBootstrapRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			test.mutate(&request)
			err := VerifyJoinerRequest(request, now)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("VerifyJoinerRequest = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestInviterRetryIdempotentAndReplayRejected(t *testing.T) {
	now := time.Now()
	inviter, _, _, adapter := testInviter(t, &now)
	joiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, joinerWG := wgKeyPair(t)
	replayID := validReplayID(t)
	request := signalled(inviter, newBootstrapRequest(t, joiner, joinerWG, replayID, "nonce-1", now))

	first, err := inviter.Handle(context.Background(), request)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	retry, err := inviter.Handle(context.Background(), request)
	if err != nil {
		t.Fatalf("Handle retry: %v", err)
	}
	if !reflect.DeepEqual(retry, first) {
		t.Fatal("retry returned a different response")
	}
	state, _ := adapter.State()
	count := 0
	for _, peer := range state.Peers {
		if slices.Equal(peer.PublicKey, joinerWG) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("peer count = %d, want 1", count)
	}

	// A different joiner claiming the same invitation is a replay.
	otherJoiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, otherWG := wgKeyPair(t)
	otherRequest := signalled(inviter, newBootstrapRequest(t, otherJoiner, otherWG, replayID, "nonce-2", now))
	if _, err := inviter.Handle(context.Background(), otherRequest); !errors.Is(err, ErrBootstrapReplay) {
		t.Fatalf("Handle replay = %v, want ErrBootstrapReplay", err)
	}
}

func TestInviterSweepRemovesExpiredPeers(t *testing.T) {
	now := time.Now()
	inviter, _, _, adapter := testInviter(t, &now)
	joiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, joinerWG := wgKeyPair(t)
	request := signalled(inviter, newBootstrapRequest(t, joiner, joinerWG, validReplayID(t), "nonce-1", now))
	if _, err := inviter.Handle(context.Background(), request); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if inviter.Active() != 1 {
		t.Fatalf("active = %d, want 1", inviter.Active())
	}

	// Same replay id retry after expiry must succeed and reinstall a fresh
	// peer instead of being treated as a live replay.
	now = now.Add(protocol.DirectBootstrapMaxLifetime + time.Minute)
	inviter.Sweep(context.Background())
	if inviter.Active() != 0 {
		t.Fatalf("active = %d after sweep, want 0", inviter.Active())
	}
	state, _ := adapter.State()
	for _, peer := range state.Peers {
		if slices.Equal(peer.PublicKey, joinerWG) {
			t.Fatal("expired peer still installed after sweep")
		}
	}
}

func TestInviterAdapterFailureReleasesAddresses(t *testing.T) {
	now := time.Now()
	inviter, _, _, adapter := testInviter(t, &now)
	joiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, joinerWG := wgKeyPair(t)
	request := signalled(inviter, newBootstrapRequest(t, joiner, joinerWG, validReplayID(t), "nonce-1", now))

	adapter.SetPeerError(errors.New("boom"))
	if _, err := inviter.Handle(context.Background(), request); err == nil {
		t.Fatal("Handle succeeded despite adapter failure")
	}
	if inviter.Active() != 0 {
		t.Fatalf("active = %d after adapter failure, want 0", inviter.Active())
	}

	// Addresses were released: the same request retried after the adapter
	// recovers succeeds.
	if _, err := inviter.Handle(context.Background(), request); err != nil {
		t.Fatalf("Handle after recovery: %v", err)
	}
	if inviter.Active() != 1 {
		t.Fatalf("active = %d, want 1", inviter.Active())
	}
}

func TestVerifyInviterResponseRejects(t *testing.T) {
	now := time.Now()
	inviter, _, _, _ := testInviter(t, &now)
	joiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	otherJoiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, joinerWG := wgKeyPair(t)
	request := signalled(inviter, newBootstrapRequest(t, joiner, joinerWG, validReplayID(t), "nonce-1", now))
	response, err := inviter.Handle(context.Background(), request)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if err := VerifyInviterResponse(response, request, now); err != nil {
		t.Fatalf("baseline VerifyInviterResponse: %v", err)
	}

	otherServiceKey, err := otherJoiner.PublicKeyBase64()
	if err != nil {
		t.Fatal(err)
	}
	tampered := response
	tampered.ReplayID = validReplayID(t)
	if err := VerifyInviterResponse(tampered, request, now); !errors.Is(err, ErrBootstrapResponse) {
		t.Fatalf("replay mismatch = %v, want ErrBootstrapResponse", err)
	}

	tampered = response
	tampered.JoinerServiceKey = otherServiceKey
	if err := VerifyInviterResponse(tampered, request, now); !errors.Is(err, ErrBootstrapResponse) {
		t.Fatalf("joiner mismatch = %v, want ErrBootstrapResponse", err)
	}

	tampered = response
	tampered.HubProHost = "100.96.0.99"
	if err := VerifyInviterResponse(tampered, request, now); !errors.Is(err, ErrBootstrapResponse) {
		t.Fatalf("tampered hubProHost = %v, want ErrBootstrapResponse", err)
	}

	tampered = response
	tampered.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	if err := VerifyInviterResponse(tampered, request, now); !errors.Is(err, ErrBootstrapResponse) {
		t.Fatalf("expired response = %v, want ErrBootstrapResponse", err)
	}

	tampered = response
	tampered.Endpoints = nil
	if err := VerifyInviterResponse(tampered, request, now); !errors.Is(err, ErrBootstrapResponse) {
		t.Fatalf("empty endpoints = %v, want ErrBootstrapResponse", err)
	}

	tampered = response
	tampered.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if err := VerifyInviterResponse(tampered, request, now); !errors.Is(err, ErrBootstrapResponse) {
		t.Fatalf("bad signature = %v, want ErrBootstrapResponse", err)
	}
}

func TestInviterAddressesDifferAcrossJoiners(t *testing.T) {
	now := time.Now()
	inviter, _, _, _ := testInviter(t, &now)
	firstJoiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	secondJoiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, firstWG := wgKeyPair(t)
	_, secondWG := wgKeyPair(t)
	first, err := inviter.Handle(context.Background(), signalled(inviter, newBootstrapRequest(t, firstJoiner, firstWG, validReplayID(t), "nonce-1", now)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := inviter.Handle(context.Background(), signalled(inviter, newBootstrapRequest(t, secondJoiner, secondWG, validReplayID(t), "nonce-2", now)))
	if err != nil {
		t.Fatal(err)
	}
	if first.JoinerAddress == second.JoinerAddress {
		t.Fatalf("two joiners received the same temporary addresses: %+v", first.JoinerAddress)
	}
	if first.InviterAddress != second.InviterAddress {
		t.Fatal("inviter address should be stable across bootstrap links")
	}
}

func TestInviterCloseAll(t *testing.T) {
	now := time.Now()
	inviter, _, _, adapter := testInviter(t, &now)
	for index := 0; index < 3; index++ {
		joiner, err := identity.Generate()
		if err != nil {
			t.Fatal(err)
		}
		_, wgKey := wgKeyPair(t)
		request := signalled(inviter, newBootstrapRequest(t, joiner, wgKey, validReplayID(t), "nonce-1", now))
		if _, err := inviter.Handle(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	if inviter.Active() != 3 {
		t.Fatalf("active = %d, want 3", inviter.Active())
	}
	inviter.CloseAll(context.Background())
	if inviter.Active() != 0 {
		t.Fatalf("active = %d after CloseAll, want 0", inviter.Active())
	}
	state, _ := adapter.State()
	if len(state.Peers) != 0 {
		t.Fatalf("peers after CloseAll = %d, want 0", len(state.Peers))
	}
}

// TestUpdateJoinerAllowedIPs proves the inviter extends an active temporary
// peer with the joiner's permanent overlay addresses (adoption path) while
// keeping the bootstrap addresses, and rejects unknown joiners and
// out-of-overlay prefixes.
func TestUpdateJoinerAllowedIPs(t *testing.T) {
	now := time.Now().UTC()
	inviterIdentity, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	inviterWG := make([]byte, 32)
	if _, err := rand.Read(inviterWG); err != nil {
		t.Fatal(err)
	}
	adapter := wireguard.NewFakeAdapter()
	if err := adapter.Up(wireguard.InterfaceConfig{
		Name: "hubnet0", Address: netip.MustParseAddr("100.96.0.1"), ListenPort: 51820,
	}); err != nil {
		t.Fatalf("adapter Up: %v", err)
	}
	inviter, err := NewInviter(InviterOptions{
		Identity:     inviterIdentity,
		WireGuardKey: inviterWG,
		Adapter:      adapter,
		HubProHost:   func() string { return "100.96.0.1" },
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewInviter: %v", err)
	}
	joiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	joinerService, err := joiner.PublicKeyBase64()
	if err != nil {
		t.Fatal(err)
	}
	joinerWG := make([]byte, 32)
	if _, err := rand.Read(joinerWG); err != nil {
		t.Fatal(err)
	}
	request := protocol.DirectBootstrapRequest{
		ReplayID:           base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xAB}, 32)),
		JoinerServiceKey:   joinerService,
		JoinerWireGuardKey: base64.StdEncoding.EncodeToString(joinerWG),
		Nonce:              "nonce-1",
		IssuedAt:           now.Add(-time.Second).Format(time.RFC3339Nano),
	}
	if err := SignJoinerRequest(&request, joiner.PrivateKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := inviter.Handle(context.Background(), signalled(inviter, request)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	state, up := adapter.State()
	if !up || len(state.Peers) != 1 {
		t.Fatalf("temporary peer not installed")
	}
	bootstrapAllowed := len(state.Peers[0].AllowedIPs)
	if bootstrapAllowed != 2 {
		t.Fatalf("bootstrap allowedIPs = %d, want 2", bootstrapAllowed)
	}

	permanent := []netip.Prefix{
		netip.MustParsePrefix("100.96.0.2/32"),
		netip.MustParsePrefix("fd48:5542:4e45::2/128"),
	}
	if err := inviter.UpdateJoinerAllowedIPs(context.Background(), joinerService, permanent); err != nil {
		t.Fatalf("UpdateJoinerAllowedIPs: %v", err)
	}
	state, _ = adapter.State()
	if len(state.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(state.Peers))
	}
	allowed := state.Peers[0].AllowedIPs
	if len(allowed) != 4 {
		t.Fatalf("allowedIPs = %v, want 4 entries", allowed)
	}
	want := map[string]bool{
		"100.127.254.2/32":           true,
		"fd48:5542:4e45:fffe::2/128": true,
		"100.96.0.2/32":              true,
		"fd48:5542:4e45::2/128":      true,
	}
	for _, prefix := range allowed {
		if !want[prefix.String()] {
			t.Errorf("unexpected allowedIP %s", prefix)
		}
		delete(want, prefix.String())
	}
	if len(want) != 0 {
		t.Errorf("missing allowedIPs %v", want)
	}

	// Unknown joiner and out-of-overlay prefix are rejected.
	unknown, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	unknownKey, _ := unknown.PublicKeyBase64()
	if err := inviter.UpdateJoinerAllowedIPs(context.Background(), unknownKey, permanent); !errors.Is(err, ErrBootstrapReplay) {
		t.Errorf("unknown joiner error = %v, want ErrBootstrapReplay", err)
	}
	if err := inviter.UpdateJoinerAllowedIPs(context.Background(), joinerService, []netip.Prefix{netip.MustParsePrefix("192.168.1.1/32")}); err == nil {
		t.Error("out-of-overlay prefix accepted")
	}
}

// The inviter's UDP listener is reachable by anyone; without the node's
// signal for the join it must not hand out a signed response (hub-pro admits
// joiners on that response).
func TestInviterRejectsUnsignalledJoin(t *testing.T) {
	now := time.Now()
	inviter, _, _, adapter := testInviter(t, &now)
	joiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	joinerWG := make([]byte, 32)
	joinerWG[0] = 9
	request := newBootstrapRequest(t, joiner, joinerWG, validReplayID(t), "nonce-1", now)
	if _, err := inviter.Handle(context.Background(), request); !errors.Is(err, ErrBootstrapRequest) {
		t.Fatalf("Handle without a node signal = %v, want ErrBootstrapRequest", err)
	}
	if state, _ := adapter.State(); len(state.Peers) != 0 {
		t.Fatalf("peers installed for an unsignalled join: %d", len(state.Peers))
	}
	inviter.Expect(request.ReplayID, "someone-else")
	if _, err := inviter.Handle(context.Background(), request); !errors.Is(err, ErrBootstrapRequest) {
		t.Fatalf("Handle for another joiner's signal = %v, want ErrBootstrapRequest", err)
	}
}
