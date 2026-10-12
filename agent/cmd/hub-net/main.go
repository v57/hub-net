// Command hub-net runs daemon or sends one command to its local socket.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	hubnet "github.com/v57/hub-net"
	"github.com/v57/hub-net/config"
	"github.com/v57/hub-net/hubalias"
	"github.com/v57/hub-net/invitation"
	"github.com/v57/hub-net/logging"
	"github.com/v57/hub-net/management"
	"github.com/v57/hub-net/membership"
	"github.com/v57/hub-net/publications"
	"github.com/v57/hub-net/supervisor"
	"github.com/v57/hub-net/wireguard"
	hubservice "github.com/v57/hub-service-go"
	"github.com/v57/hub-service-go/identity"
	"github.com/v57/hub-service-go/protocol"
)

var buildVersion = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "hub-net: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg := config.Defaults()
	flags := flag.NewFlagSet("hub-net", flag.ContinueOnError)
	stateDir := flags.String("state-dir", cfg.StateDir, "agent state directory")
	socketPath := flags.String("socket", "", "daemon command IPC socket")
	dnsListen := flags.String("dns-listen", cfg.DNSListenAddress, "reserved-suffix DNS listen address")
	logJSON := flags.Bool("log-json", true, "emit JSON structured logs")
	showVersion := flags.Bool("version", false, "print build version and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(buildVersion)
		return nil
	}
	if *socketPath == "" {
		*socketPath = filepath.Join(*stateDir, "command.sock")
	}
	if flags.NArg() > 0 {
		request, err := management.ParseCommand(flags.Args())
		if err != nil {
			return err
		}
		response, err := management.NewClient(*socketPath).Execute(context.Background(), request)
		if err != nil {
			return err
		}
		switch request.Command {
		case "join":
			fmt.Println(management.FormatJoin(*response.Joined))
		case "local":
			fmt.Println("Serving " + response.Joined.Record.Alias + " as its local agent")
		case "list":
			if output := management.FormatList(response.Items); output != "" {
				fmt.Println(output)
			}
		}
		return nil
	}

	store, err := membership.Open(*stateDir)
	if err != nil {
		return err
	}
	logger := logging.New(logging.Options{Format: logFormat(*logJSON)})
	daemon, err := hubnet.NewDaemon(func(member supervisor.Membership) (hubnet.Options, error) {
		sessionConfig := cfg
		sessionConfig.StateDir = member.StateDir
		sessionConfig.IdentityPath = member.IdentityPath
		sessionConfig.WireGuardKeyPath = member.WireGuardKeyPath
		sessionConfig.HubAddress = member.HubAddress
		sessionConfig.AgentSocketPath = filepath.Join(member.StateDir, "service.sock")
		if member.Local {
			// hub-pro proves its machine-local agent over the well-known
			// socket (HUB_NET_AGENT_SOCKET, default /run/hub-net/agent.sock).
			sessionConfig.AgentSocketPath = cfg.AgentSocketPath
		}
		sessionConfig.DNSListenAddress = *dnsListen
		// A joined membership keeps the inviter peer of its temporary
		// bootstrap link so the hub-pro control connection through the
		// inviter survives the join-time interface reconfiguration.
		initialPeers, err := invitation.LoadInviterPeers(filepath.Join(member.StateDir, invitation.InviterPeerFileName))
		if err != nil {
			return hubnet.Options{}, err
		}
		publicationsPath := member.PublicationsPath
		if publicationsPath == "" {
			publicationsPath = filepath.Join(member.StateDir, "publications.json")
		}
		shares, err := publications.Load(publicationsPath)
		if err != nil {
			return hubnet.Options{}, err
		}
		bindingKind := protocol.LocalAgentBindingJoin
		if member.Local {
			bindingKind = protocol.LocalAgentBindingMachine
		}
		return hubnet.Options{
			Config: sessionConfig, Logger: logger, Production: true,
			BindingKind:    bindingKind,
			InterfaceName:  member.InterfaceName,
			InitialShares:  shares,
			GatewayAllowed: member.GatewayAllowed,
			InitialPeers:   initialPeers,
		}, nil
	})
	if err != nil {
		return err
	}
	join, err := newJoin(store, *stateDir, logger)
	if err != nil {
		return err
	}
	service, err := management.NewService(daemon, store, join, newLocal(store))
	if err != nil {
		return err
	}
	server, err := management.NewServer(*socketPath, service)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	daemonDone := make(chan error, 1)
	go func() { daemonDone <- daemon.Run(ctx) }()
	if err := daemon.WaitRunning(ctx); err != nil {
		return err
	}
	if _, err := daemon.Restore(store); err != nil {
		return err
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(ctx) }()
	select {
	case err := <-daemonDone:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case err := <-serverDone:
		daemon.Shutdown()
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

// newJoin builds the daemon join command: it stages a fresh service + WireGuard
// key pair per invitation, performs the direct bootstrap join, persists the
// per-membership key material and the inviter peer, and returns the membership
// record the daemon adopts.
func newJoin(store *membership.Store, stateDir string, logger *slog.Logger) (management.JoinFunc, error) {
	stage, err := invitation.NewFileStore(filepath.Join(stateDir, "invitations"))
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, code string) (management.JoinResult, error) {
		decoded, err := invitation.Decode(code, time.Now())
		if err != nil {
			return management.JoinResult{}, fmt.Errorf("hub-net: join: %w", err)
		}
		transactionID := decoded.Envelope.TokenID
		staged, err := stagedJoinIdentity(ctx, stage, transactionID)
		if err != nil {
			return management.JoinResult{}, err
		}
		id, err := parseIdentityBlob(staged.Key)
		if err != nil {
			return management.JoinResult{}, err
		}
		wireGuardKey, err := base64.StdEncoding.DecodeString(staged.WireGuardKey)
		if err != nil || len(wireGuardKey) != 32 {
			return management.JoinResult{}, errors.New("hub-net: corrupt staged wireguard key")
		}
		interfaceName := nextInterfaceName(store)
		adapter := wireguard.NewPlatformAdapter(interfaceName)
		result, err := invitation.Join(ctx, invitation.JoinOptions{
			Code: code, Identity: id, WireGuardKey: wireGuardKey,
			InterfaceName: interfaceName, Adapter: adapter, Logger: logger,
		})
		if err != nil {
			return management.JoinResult{}, err
		}
		// Join left the temporary link up so the daemon session can adopt it.
		// Any failure while persisting the membership tears the link down
		// again instead of stranding an unrecorded tunnel.
		committed := false
		defer func() {
			if !committed {
				_ = adapter.Down()
			}
		}()

		// Persist the join key material into the membership the daemon will
		// adopt, and the inviter peer that keeps the temporary link alive.
		memberDir := store.MemberDir(transactionID)
		if err := os.MkdirAll(memberDir, 0o700); err != nil {
			return management.JoinResult{}, fmt.Errorf("hub-net: create membership dir: %w", err)
		}
		if err := os.WriteFile(filepath.Join(memberDir, "profile.identity"), []byte(staged.Key), 0o600); err != nil {
			return management.JoinResult{}, fmt.Errorf("hub-net: persist identity: %w", err)
		}
		if err := os.WriteFile(filepath.Join(memberDir, "wireguard.key"), wireGuardKey, 0o600); err != nil {
			return management.JoinResult{}, fmt.Errorf("hub-net: persist wireguard key: %w", err)
		}
		if err := invitation.SaveInviterPeer(
			filepath.Join(memberDir, invitation.InviterPeerFileName),
			invitation.NewInviterPeer(result),
		); err != nil {
			return management.JoinResult{}, err
		}

		// Durable recovery journal: the enrollment recorded before any local
		// commit work so an interrupted join can be resumed without rotating
		// keys or re-enrolling.
		enrollment := invitation.Enrollment{
			MembershipID: transactionID, NetworkID: result.HubNetworkID, Addresses: result.OverlayAddresses,
		}
		if err := stage.RecordEnrollment(ctx, transactionID, enrollment); err != nil {
			return management.JoinResult{}, err
		}

		record, err := joinRecord(store, transactionID, result, decoded.Node)
		if err != nil {
			return management.JoinResult{}, err
		}
		committed = true
		return management.JoinResult{
			Record: record, VirtualHost: result.HubProHost, VirtualIP: overlayIPv4(result.OverlayAddresses),
		}, nil
	}, nil
}

// newLocal builds the `hub-net local` command: a membership for the hub-pro
// running on this machine, with a fresh service identity and WireGuard key.
// Its session binds as the machine-local agent, so it can issue invitations.
func newLocal(store *membership.Store) management.LocalFunc {
	return func(ctx context.Context, address string) (membership.Record, error) {
		id, err := identity.Generate()
		if err != nil {
			return membership.Record{}, fmt.Errorf("hub-net: generate identity: %w", err)
		}
		encoded, err := id.Encode()
		if err != nil {
			return membership.Record{}, err
		}
		wireGuardKey := make([]byte, 32)
		if _, err := rand.Read(wireGuardKey); err != nil {
			return membership.Record{}, fmt.Errorf("hub-net: generate wireguard key: %w", err)
		}
		idBytes := make([]byte, 9)
		if _, err := rand.Read(idBytes); err != nil {
			return membership.Record{}, err
		}
		name, err := hubHeaderName(ctx, address, id)
		if err != nil {
			return membership.Record{}, fmt.Errorf("hub-net: read hub header at %s: %w", address, err)
		}
		records, _, err := store.Load()
		if err != nil {
			return membership.Record{}, err
		}
		usedAliases := make([]string, 0, len(records))
		usedInterfaces := make([]string, 0, len(records))
		for _, stored := range records {
			usedAliases = append(usedAliases, stored.Record.Alias)
			usedInterfaces = append(usedInterfaces, stored.Record.InterfaceName)
		}
		hubAddress, err := json.Marshal(address)
		if err != nil {
			return membership.Record{}, err
		}
		record := membership.Record{
			ID:            "local-" + base64.RawURLEncoding.EncodeToString(idBytes),
			Alias:         hubalias.Allocate(name, usedAliases),
			Header:        name,
			HubAddress:    hubAddress,
			InterfaceName: nextFreeInterface(usedInterfaces),
			Local:         true,
		}
		memberDir := store.MemberDir(record.ID)
		if err := os.MkdirAll(memberDir, 0o700); err != nil {
			return membership.Record{}, fmt.Errorf("hub-net: create membership dir: %w", err)
		}
		if err := os.WriteFile(filepath.Join(memberDir, "profile.identity"), []byte(encoded), 0o600); err != nil {
			return membership.Record{}, fmt.Errorf("hub-net: persist identity: %w", err)
		}
		if err := os.WriteFile(filepath.Join(memberDir, "wireguard.key"), wireGuardKey, 0o600); err != nil {
			return membership.Record{}, fmt.Errorf("hub-net: persist wireguard key: %w", err)
		}
		return record, nil
	}
}

// hubHeaderName reads the public hub/header display name at address.
func hubHeaderName(ctx context.Context, address string, id *identity.Identity) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	svc, err := hubservice.New(hubservice.Options{Address: address, Identity: id, Name: "hub-net"})
	if err != nil {
		return "", err
	}
	if err := svc.Start(); err != nil {
		return "", err
	}
	defer svc.Stop()
	header, err := hubservice.OneValueTyped[struct {
		Name string `json:"name"`
	}](ctx, svc, "hub/header", nil)
	if err != nil {
		return "", err
	}
	return header.Name, nil
}

// stagedJoinIdentity returns the staged identity + WireGuard key for one
// invitation transaction, generating a fresh pair on first use. Retrying the
// same invitation reuses the staged pair so a join can never rotate keys
// after a partial remote enrollment.
func stagedJoinIdentity(ctx context.Context, stage *invitation.FileStore, transactionID string) (invitation.JoinIdentity, error) {
	id, err := identity.Generate()
	if err != nil {
		return invitation.JoinIdentity{}, fmt.Errorf("hub-net: generate identity: %w", err)
	}
	encoded, err := id.Encode()
	if err != nil {
		return invitation.JoinIdentity{}, err
	}
	wireGuardKey := make([]byte, 32)
	if _, err := rand.Read(wireGuardKey); err != nil {
		return invitation.JoinIdentity{}, fmt.Errorf("hub-net: generate wireguard key: %w", err)
	}
	return stage.Stage(ctx, transactionID, invitation.JoinIdentity{
		Key:          encoded,
		WireGuardKey: base64.StdEncoding.EncodeToString(wireGuardKey),
	})
}

// parseIdentityBlob loads an encoded Bun-format identity from a temporary
// file so identity.Load's parsing and validation are reused.
func parseIdentityBlob(encoded string) (*identity.Identity, error) {
	file, err := os.CreateTemp("", "hub-net-join-identity-*")
	if err != nil {
		return nil, fmt.Errorf("hub-net: identity temp: %w", err)
	}
	path := file.Name()
	defer os.Remove(path)
	if _, err := file.WriteString(encoded); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return identity.Load(path)
}

// joinRecord builds the membership record the daemon adopts for a completed
// join.
func joinRecord(store *membership.Store, transactionID string, result invitation.JoinResult, node string) (membership.Record, error) {
	records, _, err := store.Load()
	if err != nil {
		return membership.Record{}, err
	}
	usedAliases := make([]string, 0, len(records))
	usedInterfaces := make([]string, 0, len(records))
	for _, stored := range records {
		usedAliases = append(usedAliases, stored.Record.Alias)
		usedInterfaces = append(usedInterfaces, stored.Record.InterfaceName)
	}
	hubAddress, err := json.Marshal("ws://" + result.HubProHost + ":1997")
	if err != nil {
		return membership.Record{}, err
	}
	return membership.Record{
		ID:            transactionID,
		Alias:         hubalias.Allocate(result.HubName, usedAliases),
		Header:        result.HubName,
		HubAddress:    hubAddress,
		NetworkID:     result.HubNetworkID,
		NodeURL:       node,
		InterfaceName: nextFreeInterface(usedInterfaces),
		CanonicalIPv4: overlayIPv4(result.OverlayAddresses),
		CanonicalIPv6: overlayIPv6(result.OverlayAddresses),
	}, nil
}

func nextInterfaceName(store *membership.Store) string {
	records, _, err := store.Load()
	if err != nil {
		return "hubnet0"
	}
	used := make([]string, 0, len(records))
	for _, stored := range records {
		used = append(used, stored.Record.InterfaceName)
	}
	return nextFreeInterface(used)
}

func nextFreeInterface(used []string) string {
	taken := make(map[string]bool, len(used))
	for _, name := range used {
		taken[name] = true
	}
	for index := 0; ; index++ {
		name := fmt.Sprintf("hubnet%d", index)
		if !taken[name] {
			return name
		}
	}
}

func overlayIPv4(addresses []string) string {
	for _, address := range addresses {
		if !containsColon(address) {
			return address
		}
	}
	return ""
}

func overlayIPv6(addresses []string) string {
	for _, address := range addresses {
		if containsColon(address) {
			return address
		}
	}
	return ""
}

func containsColon(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == ':' {
			return true
		}
	}
	return false
}

func logFormat(json bool) logging.Format {
	if json {
		return logging.FormatJSON
	}
	return logging.FormatText
}
