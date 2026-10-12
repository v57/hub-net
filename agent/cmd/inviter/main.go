// Command inviter is a standalone online inviter for the direct bootstrap
// join flow. It is the Linux acceptance counterpart to the inviter harness in
// the invitation package tests: it registers a service identity with
// hub-net-node (nodeclient challenge handshake), runs the HUBB bootstrap
// listener that answers signed joiner requests, and prints compact
// invitations on stdin.
//
// It intentionally reuses the production Inviter/Listener/nodeclient
// components exactly as the hub-net daemon wires them once a membership is
// joined, so a `hub-net join <code>` command can be exercised against real
// kernel WireGuard without needing a prior joined membership.
//
// Usage:
//
//	inviter -node <ws://host:port> [-state-dir <dir>] [-listen :0]
//
// Each line of stdin is a command; "invite" prints a compact code on stdout
// as `invitation <code>`. EOF stops the process.
package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	nodeprotocol "github.com/v57/hub-net-node/protocol"
	"github.com/v57/hub-net/invitation"
	"github.com/v57/hub-net/nodeclient"
	"github.com/v57/hub-net/wireguard"
	"github.com/v57/hub-service-go/identity"
	"github.com/v57/hub-service-go/protocol"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "inviter: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		node      = flag.String("node", "", "hub-net-node WebSocket endpoint (required)")
		stateDir  = flag.String("state-dir", "", "state directory (identity/wireguard key)")
		listen    = flag.String("listen", ":0", "bootstrap listener UDP bind address")
		adapterIP = flag.String("adapter-address", "100.96.0.1", "inviter WireGuard interface address (overlay IPv4)")
		wgPort    = flag.Int("wg-port", 51820, "inviter WireGuard UDP listen port")
		advertise = flag.String("advertise-address", "", "address advertised in the bootstrap candidate (default: listener local address; override for NAT/netns setups where the listener binds an unspecified address)")
		bypass    = flag.String("bypass-route", "", "comma-separated host IPs to keep routable via the default gateway after the overlay route installs")
		once      = flag.Bool("once", false, "print one invitation and exit")
		noWG      = flag.Bool("no-wg", false, "skip WireGuard interface bring-up (code generation only)")
	)
	flag.Parse()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *node == "" {
		return errors.New("-node is required (e.g. ws://base.tail6a3e13.ts.net:1964)")
	}
	if *stateDir == "" {
		*stateDir = filepath.Join(os.TempDir(), "hub-net-inviter")
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}

	// Identity + WireGuard key, persisted so a restart keeps the same
	// invitation signing key.
	id, err := loadIdentity(filepath.Join(*stateDir, "profile.identity"))
	if err != nil {
		return err
	}
	wgPrivate, err := loadWireGuardKey(filepath.Join(*stateDir, "wireguard.key"))
	if err != nil {
		return err
	}
	wgPublic, err := wireGuardPublicKey(wgPrivate)
	if err != nil {
		return err
	}
	serviceKey, err := id.PublicKeyBase64()
	if err != nil {
		return err
	}
	logger.Info("inviter identity", slog.String("serviceKey", serviceKey))

	// Build the bootstrap handler + UDP listener first. The listener owns the
	// probe socket and the declared candidate, so the node-observed endpoint
	// is the listener. It binds UDP :0 and does not depend on the WireGuard
	// interface, which is only needed to install temporary joiner peers.
	adapter := wireguard.NewPlatformAdapter("hubnet0")
	overlay, err := netip.ParseAddr(*adapterIP)
	if err != nil {
		return fmt.Errorf("invalid -adapter-address %q: %w", *adapterIP, err)
	}
	inv, err := invitation.NewInviter(invitation.InviterOptions{
		Identity:     id,
		WireGuardKey: wgPublic,
		Adapter:      adapter,
		Endpoints: func() []protocol.BootstrapEndpoint {
			return []protocol.BootstrapEndpoint{{
				Address: "0.0.0.0", Port: uint16(*wgPort), Transport: "udp",
			}}
		},
		HubProHost: func() string { return overlay.String() },
	})
	if err != nil {
		return err
	}
	defer inv.CloseAll(context.Background())

	listener, err := invitation.NewListener(invitation.ListenerOptions{
		Inviter: inv,
		Address: *listen,
		Logger:  logger,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = listener.Run(ctx) }()

	// Register with hub-net-node BEFORE the WireGuard interface comes up: the
	// overlay route (100.96.0.0/11) installed by Up would swallow the node's
	// address on a Tailscale-connected host. Registration only needs the UDP
	// listener (probe) + the WebSocket connection. -once skips registration
	// entirely (code generation only needs the identity).
	if !*once {
		client, err := nodeclient.New(nodeclient.Options{
			Endpoint: func() string { return *node },
			Identity: id,
			Logger:   logger,
			Candidates: func() []protocol.Candidate {
				address, ok := listener.Addr().(*net.UDPAddr)
				if !ok {
					return nil
				}
				candidateAddress := address.IP.String()
				if *advertise != "" {
					candidateAddress = *advertise
				}
				return []protocol.Candidate{{
					CandidateID: "inviter-bootstrap", Kind: "host", Transport: "udp",
					Address: candidateAddress, Port: uint16(address.Port), Priority: 100,
				}}
			},
			Probe: func(ctx context.Context, endpoint string, probe nodeprotocol.InvitationUDPProbe, expected string) error {
				return listener.Probe(ctx, endpoint, probe, expected)
			},
			Bootstrap: func(event nodeclient.BootstrapEvent) {
				logger.Info("bootstrap rendezvous",
					slog.String("joiner", event.JoinerKey),
					slog.String("transaction", event.TransactionID),
					slog.String("session", event.SessionID),
				)
			},
		})
		if err != nil {
			return err
		}
		go func() { _ = client.Run(ctx) }()

		// Wait until the node accepts the registration.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if client.Online() {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !client.Online() {
			return errors.New("inviter: never registered with node")
		}
		logger.Info("inviter registered with node")
	}

	// Bring up the WireGuard interface so temporary joiner peers can be
	// installed. This installs the overlay routes; restore reachability to the
	// node host afterwards with specific bypass routes if requested.
	if !*once && !*noWG {
		if err := adapter.Up(wireguard.InterfaceConfig{
			Name: "hubnet0", Address: overlay, ListenPort: uint16(*wgPort),
		}); err != nil {
			return fmt.Errorf("inviter: wireguard interface: %w", err)
		}
		defer func() { _ = adapter.Down() }()
		for _, host := range strings.Split(*bypass, ",") {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			if err := addBypassRoute(host); err != nil {
				return fmt.Errorf("inviter: bypass route %s: %w", host, err)
			}
			logger.Info("bypass route installed", slog.String("host", host))
		}
	}

	// Serve invite commands from stdin, or print one code and exit.
	if *once {
		code, err := invitation.CreateCode(id, *node)
		if err != nil {
			return fmt.Errorf("inviter: create code: %w", err)
		}
		fmt.Println(code)
		return nil
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "invite":
			code, err := invitation.CreateCode(id, *node)
			if err != nil {
				return fmt.Errorf("inviter: create code: %w", err)
			}
			fmt.Println("invitation " + code)
		case "quit":
			return nil
		default:
			fmt.Fprintln(os.Stderr, "inviter: unknown command: "+fields[0])
		}
	}
	// stdin EOF is not fatal: a background inviter must keep serving joiners
	// even when its controlling terminal goes away. Wait on the context.
	logger.Info("inviter stdin closed; serving until signal")
	<-ctx.Done()
	return nil
}

// addBypassRoute installs a /32 host route for host via the current default
// gateway. The inviter's WireGuard interface installs the frozen overlay
// prefix (100.96.0.0/11), which on a Tailscale-connected host would otherwise
// swallow the hub-net-node address (Tailscale peers live inside that range).
// A more specific /32 wins over the overlay /11, keeping the node reachable.
func addBypassRoute(host string) error {
	if _, err := netip.ParseAddr(host); err != nil {
		return fmt.Errorf("invalid bypass host %q", host)
	}
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return fmt.Errorf("resolve default route: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 3 || fields[0] != "default" {
		return errors.New("no default route to anchor bypass route")
	}
	gateway := fields[2]
	device := ""
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			device = fields[i+1]
			break
		}
	}
	if device == "" {
		return errors.New("default route has no device")
	}
	route := []string{"route", "add", host + "/32", "via", gateway, "dev", device}
	if output, err := exec.Command("ip", route...).CombinedOutput(); err != nil {
		// The route may already exist on retry; treat that as success.
		if !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("ip %s: %w (%s)", strings.Join(route, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func loadIdentity(path string) (*identity.Identity, error) {
	if raw, err := os.ReadFile(path); err == nil {
		file, err := os.CreateTemp("", "inviter-identity-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(file.Name())
		if _, err := file.Write(raw); err != nil {
			return nil, err
		}
		if err := file.Chmod(0o600); err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		return identity.Load(file.Name())
	}
	id, err := identity.Generate()
	if err != nil {
		return nil, err
	}
	encoded, err := id.Encode()
	if err != nil {
		return nil, err
	}
	return id, os.WriteFile(path, []byte(encoded), 0o600)
}

func loadWireGuardKey(path string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil && len(raw) == 32 {
		return raw, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, os.WriteFile(path, key, 0o600)
}

func wireGuardPublicKey(privateKey []byte) ([]byte, error) {
	curve := ecdh.X25519()
	key, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}
