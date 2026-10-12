package invitation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	nodeprotocol "github.com/v57/hub-net-node/protocol"
	"github.com/v57/hub-service-go/identity"
	"github.com/v57/hub-service-go/protocol"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startListener(t *testing.T, inviter *Inviter) (*Listener, context.CancelFunc) {
	t.Helper()
	listener, err := NewListener(ListenerOptions{
		Inviter: inviter,
		Address: "127.0.0.1:0",
		Logger:  testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- listener.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("listener Run did not stop")
		}
	})
	return listener, cancel
}

func TestListenerExchangeRoundTrip(t *testing.T) {
	now := time.Now()
	inviter, inviterID, _, adapter := testInviter(t, &now)
	listener, _ := startListener(t, inviter)

	joiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, joinerWG := wgKeyPair(t)
	replayID := validReplayID(t)
	request := signalled(inviter, newBootstrapRequest(t, joiner, joinerWG, replayID, "nonce-1", now))
	address := listener.Addr().(*net.UDPAddr)

	response, err := Exchange(context.Background(), address, request, ExchangeOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if err := VerifyInviterResponse(response, request, now); err != nil {
		t.Fatalf("VerifyInviterResponse: %v", err)
	}
	inviterServiceKey, _ := inviterID.PublicKeyBase64()
	if response.InviterServiceKey != inviterServiceKey {
		t.Fatal("response signed by wrong inviter")
	}
	if len(response.Endpoints) == 0 {
		t.Fatal("response carries no endpoints")
	}
	state, up := adapter.State()
	if !up || len(state.Peers) != 1 {
		t.Fatalf("temporary peer not installed: up=%v peers=%d", up, len(state.Peers))
	}
}

func TestListenerRejectsInvalidRequest(t *testing.T) {
	now := time.Now()
	inviter, _, _, _ := testInviter(t, &now)
	listener, _ := startListener(t, inviter)

	joiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, joinerWG := wgKeyPair(t)
	request := signalled(inviter, newBootstrapRequest(t, joiner, joinerWG, validReplayID(t), "nonce-bad", now))
	request.Version = 99 // invalidate after signing

	_, err = Exchange(context.Background(), listener.Addr().(*net.UDPAddr), request, ExchangeOptions{Now: func() time.Time { return now }})
	var transportError *BootstrapTransportError
	if !errors.As(err, &transportError) {
		t.Fatalf("Exchange error = %v, want BootstrapTransportError", err)
	}
	if transportError.Code != BootstrapErrorInvalid || transportError.Retryable {
		t.Fatalf("error frame = %+v, want non-retryable %s", transportError, BootstrapErrorInvalid)
	}
}

func TestListenerRejectsReplay(t *testing.T) {
	now := time.Now()
	inviter, _, _, _ := testInviter(t, &now)
	listener, _ := startListener(t, inviter)
	address := listener.Addr().(*net.UDPAddr)

	joiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, joinerWG := wgKeyPair(t)
	replayID := validReplayID(t)
	first := signalled(inviter, newBootstrapRequest(t, joiner, joinerWG, replayID, "nonce-1", now))
	if _, err := Exchange(context.Background(), address, first, ExchangeOptions{Now: func() time.Time { return now }}); err != nil {
		t.Fatalf("first Exchange: %v", err)
	}

	secondJoiner, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, secondWG := wgKeyPair(t)
	second := signalled(inviter, newBootstrapRequest(t, secondJoiner, secondWG, replayID, "nonce-2", now))
	_, err = Exchange(context.Background(), address, second, ExchangeOptions{Now: func() time.Time { return now }})
	var transportError *BootstrapTransportError
	if !errors.As(err, &transportError) {
		t.Fatalf("Exchange error = %v, want BootstrapTransportError", err)
	}
	if transportError.Code != BootstrapErrorReplay || transportError.Retryable {
		t.Fatalf("error frame = %+v, want non-retryable %s", transportError, BootstrapErrorReplay)
	}
}

func TestListenerDropsGarbage(t *testing.T) {
	now := time.Now()
	inviter, _, _, _ := testInviter(t, &now)
	listener, _ := startListener(t, inviter)

	conn, err := net.DialUDP("udp", nil, listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("not a bootstrap frame")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buffer := make([]byte, 64)
	if _, err := conn.Read(buffer); err == nil {
		t.Fatal("listener answered garbage datagram")
	}

	// Listener still serves valid traffic after the garbage.
	joiner, _ := identity.Generate()
	_, joinerWG := wgKeyPair(t)
	request := signalled(inviter, newBootstrapRequest(t, joiner, joinerWG, validReplayID(t), "nonce-ok", now))
	if _, err := Exchange(context.Background(), listener.Addr().(*net.UDPAddr), request, ExchangeOptions{Now: func() time.Time { return now }}); err != nil {
		t.Fatalf("Exchange after garbage: %v", err)
	}
}

// fakeProbeNode records the probe source and answers with the expected ticket
// id, proving the listener's node-observed endpoint equals its own address.
func fakeProbeNode(t *testing.T) (address string, observed func() net.Addr) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var mu sync.Mutex
	var source net.Addr
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, from, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			var probe nodeprotocol.InvitationUDPProbe
			if err := json.Unmarshal(buffer[:n], &probe); err != nil || probe.TokenDigest == "" {
				continue
			}
			mu.Lock()
			source = from
			mu.Unlock()
			response, _ := json.Marshal(nodeprotocol.UDPProbeResponse{
				Version: protocol.WireVersion, TicketID: probe.TokenDigest + ":" + probe.Key,
			})
			_, _ = conn.WriteToUDP(response, from)
		}
	}()
	return conn.LocalAddr().String(), func() net.Addr {
		mu.Lock()
		defer mu.Unlock()
		return source
	}
}

func TestListenerProbeFromListenerSocket(t *testing.T) {
	now := time.Now()
	inviter, _, _, _ := testInviter(t, &now)
	listener, _ := startListener(t, inviter)

	nodeAddress, observed := fakeProbeNode(t)
	probe := nodeprotocol.InvitationUDPProbe{
		Version: protocol.WireVersion, InvitationCode: "code",
		Key: "service-key", TokenDigest: "digest",
		TransactionID: "transaction",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := listener.Probe(ctx, nodeAddress, probe, "digest:service-key"); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	source := observed()
	if source == nil {
		t.Fatal("node never observed the probe")
	}
	if source.String() != listener.Addr().String() {
		t.Fatalf("node observed %s, want listener %s", source, listener.Addr())
	}
}

func TestListenerProbeTimeout(t *testing.T) {
	now := time.Now()
	inviter, _, _, _ := testInviter(t, &now)
	listener, _ := startListener(t, inviter)
	// No node responder; the probe must time out instead of hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := listener.Probe(ctx, "127.0.0.1:1", nodeprotocol.InvitationUDPProbe{
		Version: protocol.WireVersion, Key: "k", TokenDigest: "d",
		TransactionID: "t", InvitationCode: "c",
	}, "d:k")
	if err == nil {
		t.Fatal("probe unexpectedly succeeded")
	}
}

func TestListenerConcurrentExchanges(t *testing.T) {
	now := time.Now()
	inviter, _, _, adapter := testInviter(t, &now)
	listener, _ := startListener(t, inviter)
	address := listener.Addr().(*net.UDPAddr)

	const peers = 8
	var wg sync.WaitGroup
	errorsCh := make(chan error, peers)
	for i := 0; i < peers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			joiner, err := identity.Generate()
			if err != nil {
				errorsCh <- err
				return
			}
			_, joinerWG := wgKeyPair(t)
			request := signalled(inviter, newBootstrapRequest(t, joiner, joinerWG, validReplayID(t), "nonce-concurrent", now))
			response, err := Exchange(context.Background(), address, request, ExchangeOptions{Now: func() time.Time { return now }})
			if err != nil {
				errorsCh <- err
				return
			}
			if err := VerifyInviterResponse(response, request, now); err != nil {
				errorsCh <- err
			}
		}()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Fatalf("concurrent exchange: %v", err)
	}
	state, up := adapter.State()
	if !up || len(state.Peers) != peers {
		t.Fatalf("expected %d temporary peers, got up=%v peers=%d", peers, up, len(state.Peers))
	}
}

func TestListenerIdempotentRetry(t *testing.T) {
	now := time.Now()
	inviter, _, _, adapter := testInviter(t, &now)
	listener, _ := startListener(t, inviter)
	address := listener.Addr().(*net.UDPAddr)

	joiner, _ := identity.Generate()
	_, joinerWG := wgKeyPair(t)
	request := signalled(inviter, newBootstrapRequest(t, joiner, joinerWG, validReplayID(t), "nonce-retry", now))
	first, err := Exchange(context.Background(), address, request, ExchangeOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("first Exchange: %v", err)
	}
	second, err := Exchange(context.Background(), address, request, ExchangeOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("retry Exchange: %v", err)
	}
	if first.Signature != second.Signature ||
		first.ReplayID != second.ReplayID ||
		first.JoinerAddress != second.JoinerAddress ||
		first.InviterAddress != second.InviterAddress {
		t.Fatal("retry returned a different response")
	}
	state, _ := adapter.State()
	if len(state.Peers) != 1 {
		t.Fatalf("retry installed a second peer: %d", len(state.Peers))
	}
}
