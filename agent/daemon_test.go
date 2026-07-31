package hubnet

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/v57/hub-net/config"
	"github.com/v57/hub-net/membership"
	"github.com/v57/hub-net/supervisor"
	"github.com/v57/hub-net/translation"
	"github.com/v57/hub-net/wireguard"
)

type daemonTranslationBackend struct {
	installed map[string]translation.Allocation
}

func (b *daemonTranslationBackend) Routes() ([]netip.Prefix, error) { return nil, nil }
func (b *daemonTranslationBackend) Install(name string, allocation translation.Allocation) error {
	if b.installed == nil {
		b.installed = make(map[string]translation.Allocation)
	}
	b.installed[name] = allocation
	return nil
}
func (b *daemonTranslationBackend) Remove(name string, _ translation.Allocation) error {
	delete(b.installed, name)
	return nil
}

func TestDaemonStartsWithoutConstructingSingletonSession(t *testing.T) {
	var calls atomic.Int32
	daemon, err := NewDaemon(func(supervisor.Membership) (Options, error) {
		calls.Add(1)
		return Options{}, errors.New("must not be called without membership")
	})
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	time.Sleep(10 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("session factory calls = %d, want 0", got)
	}
	if got := daemon.Sessions(); len(got) != 0 {
		t.Fatalf("sessions = %#v, want empty", got)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context canceled", err)
	}
}

func TestDaemonRestorePersistsAndCleansTranslation(t *testing.T) {
	store, err := membership.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	record := membership.Record{ID: "one", Alias: "home", Header: "Home", HubAddress: json.RawMessage(`1997`),
		NetworkID: "network", NodeURL: "wss://node", InterfaceName: "hubnet1"}
	if err := store.Stage(record); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Commit(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	backend := &daemonTranslationBackend{}
	allocator, _ := translation.NewAllocator(backend)
	manager, _ := translation.NewManager(allocator, backend)
	daemon, err := NewDaemonWithTranslation(func(m supervisor.Membership) (Options, error) {
		cfg := config.Defaults()
		cfg.StateDir, cfg.IdentityPath, cfg.WireGuardKeyPath = m.StateDir, m.IdentityPath, m.WireGuardKeyPath
		return Options{Config: cfg, Adapter: wireguard.NewFakeAdapter(), InterfaceName: m.InterfaceName}, nil
	}, manager)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	time.Sleep(10 * time.Millisecond)
	diagnostics, err := daemon.Restore(store)
	if err != nil || len(diagnostics) != 0 {
		t.Fatalf("Restore diagnostics=%+v err=%v", diagnostics, err)
	}
	records, _, err := store.Load()
	if err != nil || records[0].Record.TranslatedIPv4 == "" || records[0].Record.TranslatedIPv6 == "" {
		t.Fatalf("persisted translation records=%+v err=%v", records, err)
	}
	if _, ok := backend.installed[stored.Record.InterfaceName]; ok {
		t.Fatal("translation installed before interface activation")
	}
	records, _, _ = store.Load()
	if _, err := manager.Activate(record.ID, record.InterfaceName,
		records[0].Record.TranslatedIPv4, records[0].Record.TranslatedIPv6); err != nil {
		t.Fatalf("activate translation: %v", err)
	}
	if err := daemon.Remove(record.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := backend.installed[stored.Record.InterfaceName]; ok {
		t.Fatal("translation leaked after remove")
	}
	cancel()
	<-done
}
