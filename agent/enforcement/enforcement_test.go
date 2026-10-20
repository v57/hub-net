package enforcement

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	protocol "github.com/v57/hub-net-node/models"
)

func TestExactTCPAndUDPAuthorizationRejectsScans(t *testing.T) {
	now := time.Now().UTC()
	for _, networkProtocol := range []string{"tcp", "udp"} {
		t.Run(networkProtocol, func(t *testing.T) {
			backend := &MemoryBackend{}
			manager, _ := New(backend)
			manager.now = func() time.Time { return now }
			grant := validGrant(now, networkProtocol)
			if err := manager.Authorize(grant); err != nil {
				t.Fatal(err)
			}
			source := netip.MustParseAddr(grant.CallerAddress)
			destination := netip.MustParseAddr(grant.DestinationAddress)
			if !backend.Allowed(networkProtocol, source, destination, 9001, now) {
				t.Fatal("exact signed tuple denied")
			}
			if backend.Allowed(networkProtocol, source, destination, 9002, now) {
				t.Fatal("unshared port allowed")
			}
			if backend.Allowed("udp", source, destination, 9001, now) == (networkProtocol == "tcp") {
				t.Fatal("wrong protocol allowed")
			}
			if backend.Allowed(networkProtocol, netip.MustParseAddr("100.96.0.99"), destination, 9001, now) {
				t.Fatal("wrong caller address allowed")
			}
		})
	}
}

func TestGenerationRevocationRemovesRulesAndTerminatesFlows(t *testing.T) {
	now := time.Now().UTC()
	backend := &MemoryBackend{}
	manager, _ := New(backend)
	manager.now = func() time.Time { return now }
	if err := manager.Authorize(validGrant(now, "tcp")); err != nil {
		t.Fatal(err)
	}
	if err := manager.UpdateGeneration("resource-1", 5, true); err != nil {
		t.Fatal(err)
	}
	if len(manager.Rules()) != 0 {
		t.Fatal("stale generation rule retained")
	}
	if got := backend.Terminated(); len(got) != 1 || got[0] != "resource-1" {
		t.Fatalf("terminated = %v", got)
	}
}

func TestExpiredAndCrossFamilyAuthorizationRejected(t *testing.T) {
	now := time.Now().UTC()
	manager, _ := New(&MemoryBackend{})
	manager.now = func() time.Time { return now }
	expired := validGrant(now.Add(-2*time.Minute), "tcp")
	if err := manager.Authorize(expired); err == nil {
		t.Fatal("expired authorization accepted")
	}
	crossFamily := validGrant(now, "tcp")
	crossFamily.CallerAddress = "fd48:5542:4e45::3"
	if err := manager.Authorize(crossFamily); err == nil {
		t.Fatal("cross-family authorization accepted")
	}
}

func TestPruneExpiredRemovesRuleFromBackend(t *testing.T) {
	now := time.Now().UTC()
	backend := &MemoryBackend{}
	manager, _ := New(backend)
	manager.now = func() time.Time { return now }
	if err := manager.Authorize(validGrant(now, "tcp")); err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Minute)
	if err := manager.PruneExpired(); err != nil {
		t.Fatal(err)
	}
	if len(manager.Rules()) != 0 {
		t.Fatal("expired authorization retained")
	}
	backend.mu.Lock()
	backendRuleCount := len(backend.rules)
	backend.mu.Unlock()
	if backendRuleCount != 0 {
		t.Fatal("expired rule retained by backend")
	}
}

func TestExpiryLoopRemovesRuleWithoutNewGrant(t *testing.T) {
	backend := &MemoryBackend{}
	manager, _ := New(backend)
	grant := validGrant(time.Now().Add(-59_990*time.Millisecond), "tcp")
	if err := manager.Authorize(grant); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- manager.RunExpiryLoop(ctx, time.Millisecond) }()

	deadline := time.After(time.Second)
	for {
		backend.mu.Lock()
		count := len(backend.rules)
		backend.mu.Unlock()
		if count == 0 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("expiry loop stopped early: %v", err)
		case <-deadline:
			t.Fatal("expiry loop did not remove expired rule")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expiry loop = %v", err)
	}
}

func TestExpiryLoopRejectsInvalidIntervalAndReportsBackendFailure(t *testing.T) {
	manager, _ := New(&MemoryBackend{})
	if err := manager.RunExpiryLoop(context.Background(), 0); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("invalid interval = %v", err)
	}

	now := time.Now()
	backend := &failingBackend{}
	manager, _ = New(backend)
	manager.now = func() time.Time { return now }
	if err := manager.Authorize(validGrant(now, "tcp")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	backend.fail = true
	if err := manager.RunExpiryLoop(context.Background(), time.Millisecond); err == nil {
		t.Fatal("backend failure not returned")
	}
}

func TestBackendFailureRollsBackManagerState(t *testing.T) {
	now := time.Now().UTC()
	backend := &failingBackend{}
	manager, _ := New(backend)
	manager.now = func() time.Time { return now }
	if err := manager.Authorize(validGrant(now, "tcp")); err != nil {
		t.Fatal(err)
	}
	before := manager.Rules()

	backend.fail = true
	second := validGrant(now, "udp")
	if err := manager.Authorize(second); err == nil {
		t.Fatal("backend failure accepted")
	}
	if got := manager.Rules(); !slices.Equal(got, before) {
		t.Fatalf("rules changed after authorize failure: %v", got)
	}
	if err := manager.UpdateGeneration("resource-1", 5, false); err == nil {
		t.Fatal("backend revoke failure accepted")
	}
	if got := manager.Rules(); !slices.Equal(got, before) {
		t.Fatalf("rules changed after revoke failure: %v", got)
	}
}

type failingBackend struct {
	MemoryBackend
	fail bool
}

func (b *failingBackend) ReplaceRules(rules []Rule) error {
	if b.fail {
		return errors.New("injected")
	}
	return b.MemoryBackend.ReplaceRules(rules)
}

func validGrant(now time.Time, networkProtocol string) protocol.ConnectionGrant {
	return protocol.ConnectionGrant{
		ResourceID: "resource-1", ProviderID: "provider-1",
		CallerAddress: "100.96.0.3", DestinationAddress: "100.96.0.2",
		DestinationPort: 9001, Protocol: networkProtocol, Generation: 4,
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
}

func TestRevokeSourcesDropsThePeersRulesOnly(t *testing.T) {
	now := time.Now().UTC()
	backend := &MemoryBackend{}
	manager, _ := New(backend)
	manager.now = func() time.Time { return now }
	revoked := validGrant(now, "tcp")
	kept := validGrant(now, "tcp")
	kept.CallerAddress = "100.96.0.4"
	second := validGrant(now, "tcp")
	second.ResourceID, second.DestinationPort = "resource-2", 22
	for _, grant := range []protocol.ConnectionGrant{revoked, kept, second} {
		if err := manager.Authorize(grant); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.AllowControl([]string{"100.96.0.2"}, 1997); err != nil {
		t.Fatal(err)
	}
	if err := manager.RevokeSources([]netip.Addr{netip.MustParseAddr("100.96.0.3")}); err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("100.96.0.3")
	destination := netip.MustParseAddr("100.96.0.2")
	if backend.Allowed("tcp", source, destination, 9001, now) || backend.Allowed("tcp", source, destination, 22, now) {
		t.Fatal("revoked source still allowed")
	}
	if !backend.Allowed("tcp", netip.MustParseAddr("100.96.0.4"), destination, 9001, now) {
		t.Fatal("other caller lost its grant")
	}
	if !backend.Allowed("tcp", netip.MustParseAddr("100.96.0.9"), destination, 1997, now) {
		t.Fatal("hub control rule removed")
	}
	if got := backend.Terminated(); len(got) != 2 {
		t.Fatalf("terminated = %v, want both of the source's resources", got)
	}
	if err := manager.RevokeSources(nil); err != nil {
		t.Fatal(err)
	}
}
