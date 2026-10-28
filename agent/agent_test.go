package hubnet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/v57/hub-net/config"
	"github.com/v57/hub-net/keychain"
	"github.com/v57/hub-net/platform"
	"github.com/v57/hub-net/profile"
	"github.com/v57/hub-net/version"
	"github.com/v57/hub-net/wireguard"
)

func TestProductionPreflightFailsBeforeIdentityCreation(t *testing.T) {
	cfg := newConfig(t)
	agent, err := New(Options{
		Config:     cfg,
		Production: true,
		Preflight: func() error {
			return platform.ErrMissingPrivileges
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = agent.Prepare(context.Background())
	if !errors.Is(err, platform.ErrMissingPrivileges) {
		t.Fatalf("Prepare err = %v, want ErrMissingPrivileges", err)
	}
	if _, statErr := os.Stat(cfg.IdentityPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("identity created before preflight: %v", statErr)
	}
	if agent.Profile() != nil {
		t.Fatal("profile created before preflight")
	}
}

func TestInterfaceNameDefaultsAndCanBeOverridden(t *testing.T) {
	defaultAgent, err := New(Options{Config: newConfig(t)})
	if err != nil {
		t.Fatalf("New default: %v", err)
	}
	if defaultAgent.interfaceName != "hubnet0" {
		t.Fatalf("default interface = %q, want hubnet0", defaultAgent.interfaceName)
	}

	customAgent, err := New(Options{
		Config:        newConfig(t),
		InterfaceName: "hubnet-provider",
	})
	if err != nil {
		t.Fatalf("New custom: %v", err)
	}
	if customAgent.interfaceName != "hubnet-provider" {
		t.Fatalf("custom interface = %q, want hubnet-provider", customAgent.interfaceName)
	}
}

// newConfig returns a config rooted under a temp dir so Prepare does not touch
// the system state directory.
func newConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.StateDir = filepath.Join(t.TempDir(), "state")
	cfg.IdentityPath = filepath.Join(cfg.StateDir, config.DefaultIdentityFile)
	cfg.WireGuardKeyPath = filepath.Join(cfg.StateDir, config.DefaultWireGuardKeyFile)
	cfg.AgentSocketPath = shortSocketPath(t)
	cfg.HubAddress = 1997
	return cfg
}

// shortSocketPath returns a short Unix socket path under the system temp dir.
// macOS caps Unix socket paths near 104 bytes, and t.TempDir() plus a long
// test name overflows that. Prepare binds the socket synchronously, so the
// path must fit at construction time.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return filepath.Join(os.TempDir(), "hn-"+hex.EncodeToString(buf[:])+".sock")
}

func TestPrepareLoadsAndDerivesKeys(t *testing.T) {
	agent, err := New(Options{Config: newConfig(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	snap := agent.profile.Snapshot()
	if snap.State != profile.StateUnregistered {
		t.Fatalf("state = %s, want unregistered", snap.State)
	}
	if len(snap.WireGuardPubKey) != keychain.PrivateKeyLength {
		t.Fatalf("wireguard public key length = %d, want %d", len(snap.WireGuardPubKey), keychain.PrivateKeyLength)
	}
}

func TestPrepareIsIdempotentAcrossInstances(t *testing.T) {
	cfg := newConfig(t)

	first, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatalf("New first: %v", err)
	}
	if err := first.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare first: %v", err)
	}
	firstSnap := first.profile.Snapshot()

	second, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatalf("New second: %v", err)
	}
	if err := second.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare second: %v", err)
	}
	secondSnap := second.profile.Snapshot()

	if firstSnap.Key != secondSnap.Key {
		t.Fatalf("profile identity not persistent: %s != %s", firstSnap.Key, secondSnap.Key)
	}
	if firstSnap.WireGuardPubKey == nil || string(firstSnap.WireGuardPubKey) != string(secondSnap.WireGuardPubKey) {
		t.Fatalf("wireguard public key not persistent")
	}
}

func TestVersionMatchesProtocol(t *testing.T) {
	got := version.String()
	if got == "" {
		t.Fatalf("version string empty")
	}
	if version.Major != wireGuardExpectedWireVersion {
		t.Fatalf("version.Major = %d, want %d", version.Major, wireGuardExpectedWireVersion)
	}
}

// wireGuardExpectedWireVersion is kept here to avoid importing version's
// indirect protocol dependency in tests that only care about the constant.
const wireGuardExpectedWireVersion = 1

func TestAdapterDefaultsToFake(t *testing.T) {
	agent, err := New(Options{Config: newConfig(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := agent.Adapter().(*wireguard.FakeAdapter); !ok {
		t.Fatalf("expected FakeAdapter by default")
	}
}

func TestResolverPreparedInactive(t *testing.T) {
	agent, err := New(Options{Config: newConfig(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if agent.Resolver() == nil {
		t.Fatal("resolver is nil")
	}
	if _, err := agent.Resolver().Lookup("missing.hub.invalid"); err == nil {
		t.Fatal("inactive resolver unexpectedly answered")
	}
}

func TestConfigureInterfaceUsesRegisteredOverlayAndRollsBack(t *testing.T) {
	adapter := wireguard.NewFakeAdapter()
	agent, err := New(Options{Config: newConfig(t), Adapter: adapter})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	agent.profile.ConfirmRegistration("100.96.0.42", "network", 1)
	if err := agent.configureInterface(); err != nil {
		t.Fatalf("configureInterface: %v", err)
	}
	state, up := adapter.State()
	if !up {
		t.Fatal("wireguard interface not up")
	}
	if got := state.Address.String(); got != "100.96.0.42" {
		t.Fatalf("address = %s, want 100.96.0.42", got)
	}
	if state.ListenPort != wireguard.DefaultPort {
		t.Fatalf("listen port = %d, want %d", state.ListenPort, wireguard.DefaultPort)
	}
	if len(state.PrivateKey) != keychain.PrivateKeyLength {
		t.Fatalf("private key length = %d", len(state.PrivateKey))
	}
	if err := agent.stopInterface(); err != nil {
		t.Fatalf("stopInterface: %v", err)
	}
	if _, up := adapter.State(); up {
		t.Fatal("wireguard interface remains up")
	}
}

// A member that was on the Hub before keeps its earlier addresses there while
// its join may have recorded new ones: the interface takes the addresses of
// the latest hub/net/bind, both families, and the caller hears of them so a
// restart comes up with them.
func TestConfigureInterfaceTakesTheRegisteredAddressesAndReportsThem(t *testing.T) {
	adapter := wireguard.NewFakeAdapter()
	var reported []string
	agent, err := New(Options{
		Config: newConfig(t), Adapter: adapter,
		OverlayAddress: "100.96.0.4", OverlayIPv6: "fd48:5542:4e45::4",
		OnRegistered: func(ipv4, ipv6 string) { reported = append(reported, ipv4, ipv6) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := agent.bringUpInterface(agent.knownAddress, agent.knownIPv6); err != nil {
		t.Fatalf("bringUpInterface: %v", err)
	}
	if state, _ := adapter.State(); state.Address.String() != "100.96.0.4" || state.AddressIPv6.String() != "fd48:5542:4e45::4" {
		t.Fatalf("restart addresses = %s %s", state.Address, state.AddressIPv6)
	}
	agent.profile.ConfirmRegistration("100.96.0.3", "network", 1)
	agent.profile.SetOverlayIPv6("fd48:5542:4e45::3")
	if err := agent.configureInterface(); err != nil {
		t.Fatalf("configureInterface: %v", err)
	}
	state, up := adapter.State()
	if !up || state.Address.String() != "100.96.0.3" || state.AddressIPv6.String() != "fd48:5542:4e45::3" {
		t.Fatalf("interface = %v %s %s, want the registered addresses", up, state.Address, state.AddressIPv6)
	}
	if len(reported) != 2 || reported[0] != "100.96.0.3" || reported[1] != "fd48:5542:4e45::3" {
		t.Fatalf("reported %v", reported)
	}
	if agent.OverlayAddress() != "100.96.0.3" || agent.OverlayIPv6() != "fd48:5542:4e45::3" {
		t.Fatalf("live addresses %s %s", agent.OverlayAddress(), agent.OverlayIPv6())
	}
}

func TestConfigureInterfaceFailsClosed(t *testing.T) {
	for _, address := range []string{"", "192.0.2.1", "not-an-address"} {
		t.Run(address, func(t *testing.T) {
			adapter := wireguard.NewFakeAdapter()
			agent, err := New(Options{Config: newConfig(t), Adapter: adapter})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := agent.Prepare(context.Background()); err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			agent.profile.ConfirmRegistration(address, "network", 1)
			if err := agent.configureInterface(); err == nil {
				t.Fatal("configureInterface unexpectedly succeeded")
			}
			if _, up := adapter.State(); up {
				t.Fatal("wireguard interface left up after failure")
			}
		})
	}
}

func TestConfigureInterfaceUpFailureRollsBack(t *testing.T) {
	adapter := wireguard.NewFakeAdapter()
	agent, err := New(Options{Config: newConfig(t), Adapter: adapter})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	agent.profile.ConfirmRegistration("100.96.0.43", "network", 1)
	adapter.SetUpError(errors.New("injected setup failure"))
	if err := agent.configureInterface(); err == nil {
		t.Fatal("configureInterface unexpectedly succeeded")
	}
	if _, up := adapter.State(); up {
		t.Fatal("wireguard interface left up after setup failure")
	}
}

func TestPrepareClearsRetiredPortGrants(t *testing.T) {
	cfg := newConfig(t)
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ports := filepath.Join(cfg.StateDir, "ports.json")
	if err := os.WriteFile(ports, []byte(`{"global":{"tcp":[22]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	agent, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ports); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ports.json kept: %v", err)
	}
}
