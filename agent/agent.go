// Package hubnet provides the hub-net agent entry point.
//
// The agent owns the local WireGuard interface, the local IPC server that
// issues share attestations, and the Hub service connection that registers
// the network profile and exposes permission-controlled APIs. This scaffold
// (HN-300) wires the pieces together with deterministic, in-memory defaults
// so later tasks (HN-301 onward) can replace stubs without changing the
// public surface.
//
// On unsupported platforms or when privilege is missing, the agent fails
// safely: it reports unavailable and does not advertise a working profile
// (network-agent spec "Unsupported platforms fail safely").
package hubnet

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/v57/channel-go/channelgo"
	"github.com/v57/hub-net-node/identity"
	protocol "github.com/v57/hub-net-node/models"
	nodeprotocol "github.com/v57/hub-net-node/protocol"
	"github.com/v57/hub-net/config"
	"github.com/v57/hub-net/connection"
	"github.com/v57/hub-net/control"
	"github.com/v57/hub-net/dnsresolver"
	"github.com/v57/hub-net/enforcement"
	"github.com/v57/hub-net/gateway"
	"github.com/v57/hub-net/grant"
	"github.com/v57/hub-net/hubconn"
	"github.com/v57/hub-net/hubconn/network"
	"github.com/v57/hub-net/invitation"
	"github.com/v57/hub-net/ipc"
	"github.com/v57/hub-net/keychain"
	"github.com/v57/hub-net/logging"
	"github.com/v57/hub-net/netapi"
	"github.com/v57/hub-net/nodeclient"
	"github.com/v57/hub-net/peerlink"
	"github.com/v57/hub-net/platform"
	"github.com/v57/hub-net/profile"
	"github.com/v57/hub-net/publications"
	"github.com/v57/hub-net/version"
	"github.com/v57/hub-net/wireguard"
	hubservice "github.com/v57/hub-service-go"
)

// Agent is the hub-net process. Construct with New and run with Run.
type Agent struct {
	mu         sync.Mutex
	config     config.Config
	logger     *slog.Logger
	identitySt *keychain.IdentityStorage
	wgSt       *keychain.WireGuardStorage
	adapter    wireguard.Adapter
	profile    *profile.Profile
	registrar  *profile.Registrar
	ipcServer  *ipc.Server
	ipcCancel  context.CancelFunc
	resolver   *dnsresolver.Resolver
	dnsServer  *dnsresolver.Server
	hubService *hubconn.Service
	control    *control.Controller
	profileID  *identity.Identity
	// deviceKey certifies profileID on every Hub connect, so hubs key this
	// agent's membership as device:<deviceID>. Nil connects as a plain key.
	deviceKey *hubservice.DeviceKey
	wgPrivate []byte
	started   bool
	prepared  bool
	cancelRun context.CancelFunc
	networkUp bool

	// Grant/connection/enforcement wiring (HN-308/310). The verifier is built
	// lazily from the first signature-verified grant, since hub-server does not
	// expose its signing key over the register path today. The connection
	// manager is constructed in Prepare from injected or default adapters.
	connections        *connection.Manager
	grantVerifier      *grant.Verifier
	enforcementMgr     *enforcement.Manager
	enforcementBackend enforcement.Backend
	production         bool
	bindingKind        protocol.LocalAgentBindingKind
	knownAddress       netip.Addr
	knownIPv6          netip.Addr
	interfaceAddress   netip.Addr
	interfaceIPv6      netip.Addr
	onRegistered       func(ipv4, ipv6 string)
	// memberProfiles is the latest network/agents/list snapshot and
	// memberPeers the member WireGuard peers installed from it (hub host
	// agent only), keyed by base64 WireGuard key. Guarded by mu.
	memberProfiles []protocol.AgentProfile
	memberPeers    map[string][]netip.Prefix
	// revokedPeers holds the base64 WireGuard keys of revoked devices from
	// network/devices/revoked; revokedMembers their device:<id> member keys.
	// Neither is ever installed or authorized as a peer. Guarded by mu.
	revokedPeers   map[string]struct{}
	revokedMembers map[string]struct{}
	// peerSources remembers the overlay addresses seen for each WireGuard
	// key (member lists, authorized grants), so a revocation that arrives
	// after the member left the list still finds its firewall rules.
	peerSources      map[string][]netip.Addr
	interfaceName    string
	initialPeers     []wireguard.PeerConfig
	candidateChecker connection.CandidateChecker
	handshakeChecker connection.HandshakeChecker
	preflight        func() error
	onConnect        func(context.Context, *channelgo.Sender)
	activateNetwork  func() error
	initialShares    []publications.Entry
	gatewayBackend   gateway.Backend
	gatewayAllowed   bool
	gatewayActive    bool
	// gatewayMu serializes enabling and disabling the gateway, which wait on
	// hub-server outside mu.
	gatewayMu sync.Mutex

	// Trusted per-resource authorization generations. The production agent
	// populates this from a network/resource/generations subscription; the
	// test harness injects values directly.
	genMu       sync.RWMutex
	generations map[string]uint64
	netUsers    *netapi.Registry
	// nodeClient keeps the online-inviter registration live against
	// hub-net-node; NodeOnline reports its lease state.
	nodeClient *nodeclient.Client
	// links runs this session's peer links (network/links grants).
	links        *peerlink.Manager
	nodeEndpoint string
	// inviter handles signed joiner direct-bootstrap requests once the node
	// pairs a joiner with this agent; bootstrapListener owns the UDP socket
	// that accepts the framed requests and sends the node probe.
	inviter           *invitation.Inviter
	bootstrapListener *invitation.Listener
}

// Options configures Agent construction.
type Options struct {
	Config  config.Config
	Logger  *slog.Logger
	Adapter wireguard.Adapter
	// DNSInstaller applies suffix-scoped host DNS configuration. HN-311
	// packaging supplies the privileged platform implementation.
	DNSInstaller dnsresolver.Installer
	DNSUpstream  dnsresolver.Exchange
	// CandidateChecker verifies candidate reachability for connection.Manager.
	// Defaults to a checker that fails closed (returns an error) until the
	// real UDP reachability path lands in HN-308/HN-400; tests inject a fake.
	CandidateChecker connection.CandidateChecker
	// HandshakeChecker confirms a WireGuard handshake completed. Same default
	// and injection policy as CandidateChecker.
	HandshakeChecker connection.HandshakeChecker
	// EnforcementBackend is the platform firewall backend for per-resource
	// transport authorization. Defaults to the platform backend (Linux
	// nftables; other platforms fail closed with ErrPlatformUnsupported).
	// Tests inject enforcement.MemoryBackend to avoid privilege.
	EnforcementBackend enforcement.Backend
	// Production selects real platform networking and requires a successful
	// privilege preflight before identity creation or Hub registration.
	Production bool
	// InterfaceName selects the platform tunnel interface. Empty defaults to
	// hubnet0. Acceptance environments use distinct names for isolated agents.
	InterfaceName string
	// InitialPeers are installed on the WireGuard interface during
	// configureInterface (after registration). Joined memberships use them to
	// keep the inviter peer of the temporary bootstrap link, so the hub-server
	// control connection through the inviter survives the interface
	// reconfiguration that replaces the join-time link.
	InitialPeers []wireguard.PeerConfig
	// Preflight overrides the production probe in tests.
	Preflight func() error
	// OnConnect runs after profile, interface, and DNS activation on every Hub
	// connection. Multi-Hub daemon uses it to read one hub/header value,
	// cancel that stream, and persist refreshed display metadata.
	OnConnect func(context.Context, *channelgo.Sender)
	// ActivateNetwork installs per-Hub policy routing and translation after
	// WireGuard interface creation but before DNS/application exposure.
	ActivateNetwork func() error
	// InitialShares are persisted daemon-owned publications declared before
	// Start so connection and reconnect publish the complete desired set.
	InitialShares []publications.Entry
	// GatewayAllowed restores explicit per-Hub gateway serving intent.
	// False is always the default for new and migrated memberships.
	GatewayAllowed bool
	// GatewayBackend owns forwarding, firewall, NAT, and flow teardown.
	GatewayBackend gateway.Backend
	// OverlayAddress is a joined member's permanent IPv4 overlay address. Such
	// a member reaches hub-server only through the tunnel, so the session brings
	// the interface up with it (and InitialPeers) before connecting.
	OverlayAddress string
	// OverlayIPv6 is the member's IPv6 overlay address, brought up with
	// OverlayAddress.
	OverlayIPv6 string
	// OnRegistered receives the overlay addresses the Hub assigned at every
	// hub/net/bind, so the caller can keep the membership record in step: a
	// restart brings the interface up with them before it can ask again.
	OnRegistered func(ipv4, ipv6 string)
	// BindingKind is sent with hub/net/bind on every connect. Empty means
	// "machine": the agent on the same host as hub-server, proven over the local
	// agent socket. Memberships created by an invitation join use "join".
	BindingKind protocol.LocalAgentBindingKind
}

// New constructs an Agent. Defaults are applied; the caller may override the
// adapter (e.g. wireguard.NewFakeAdapter for unsupported platforms).
func New(options Options) (*Agent, error) {
	cfg := options.Config
	if err := cfg.Resolve(); err != nil {
		return nil, err
	}
	if err := cfg.EnsureStateDir(); err != nil {
		return nil, err
	}
	logger := options.Logger
	if logger == nil {
		logger = logging.New(logging.Options{})
	}
	interfaceName := options.InterfaceName
	if interfaceName == "" {
		interfaceName = "hubnet0"
	}
	adapter := options.Adapter
	if adapter == nil {
		if options.Production {
			adapter = wireguard.NewPlatformAdapter(interfaceName)
		} else {
			adapter = wireguard.NewFakeAdapter()
		}
	}
	installer := options.DNSInstaller
	if installer == nil {
		if options.Production {
			// DNS packets stay on loopback, but systemd-resolved attaches
			// route-only domain policy to the WireGuard link. Installation is
			// deferred until registration creates that link.
			installer = dnsresolver.NewPlatformInstaller(interfaceName)
		} else {
			installer = &dnsresolver.MemoryInstaller{}
		}
	}
	resolver := dnsresolver.New()
	preflight := options.Preflight
	if options.Production && preflight == nil {
		preflight = platform.Preflight
	}
	enforcementBackend := options.EnforcementBackend
	if enforcementBackend == nil && !options.Production {
		enforcementBackend = &enforcement.MemoryBackend{}
	}
	gatewayBackend := options.GatewayBackend
	if gatewayBackend == nil {
		if options.Production {
			gatewayBackend, _ = gateway.NewPlatformBackend()
		} else {
			gatewayBackend = &gateway.MemoryBackend{}
		}
	}
	return &Agent{
		config:             cfg,
		logger:             logger,
		identitySt:         keychain.NewIdentityStorage(cfg.IdentityPath),
		wgSt:               keychain.NewWireGuardStorage(cfg.WireGuardKeyPath),
		adapter:            adapter,
		resolver:           resolver,
		candidateChecker:   options.CandidateChecker,
		handshakeChecker:   options.HandshakeChecker,
		preflight:          preflight,
		onConnect:          options.OnConnect,
		activateNetwork:    options.ActivateNetwork,
		initialShares:      append([]publications.Entry(nil), options.InitialShares...),
		gatewayBackend:     gatewayBackend,
		gatewayAllowed:     options.GatewayAllowed,
		enforcementBackend: enforcementBackend,
		production:         options.Production,
		bindingKind:        options.BindingKind,
		knownAddress:       parseOptionalAddr(options.OverlayAddress),
		knownIPv6:          parseOptionalAddr(options.OverlayIPv6),
		onRegistered:       options.OnRegistered,
		interfaceName:      interfaceName,
		initialPeers:       append([]wireguard.PeerConfig(nil), options.InitialPeers...),
		generations:        make(map[string]uint64),
		netUsers:           netapi.NewRegistry(filepath.Join(cfg.StateDir, "revoked-users.json")),
		dnsServer: &dnsresolver.Server{
			Resolver:  resolver,
			Installer: installer,
			Upstream:  options.DNSUpstream,
		},
	}, nil
}

// Config returns the resolved configuration.
func (a *Agent) Config() config.Config { return a.config }

// Adapter returns the configured WireGuard adapter.
func (a *Agent) Adapter() wireguard.Adapter { return a.adapter }

// Resolver returns the reserved-suffix DNS resource view.
func (a *Agent) Resolver() *dnsresolver.Resolver { return a.resolver }

// Logger returns the agent logger.
func (a *Agent) Logger() *slog.Logger { return a.logger }

// Version reports the agent build version.
func (a *Agent) Version() string { return version.String() }

// Prepare loads persistent material and constructs runtime components without
// starting Hub/network activity. It is safe to call before Run, and Run calls
// it internally when the caller has not. Calling Prepare twice is an error.
func (a *Agent) Prepare(ctx context.Context) error {
	a.mu.Lock()
	if a.prepared {
		a.mu.Unlock()
		return errors.New("hubnet: already prepared")
	}
	a.prepared = true
	a.mu.Unlock()
	_ = ctx

	if a.preflight != nil {
		if err := a.preflight(); err != nil {
			return fmt.Errorf("hubnet: platform preflight: %w", err)
		}
	}

	profileID, err := a.identitySt.LoadOrGenerate()
	if err != nil {
		return fmt.Errorf("hubnet: load profile identity: %w", err)
	}
	wgPrivate, err := a.wgSt.LoadOrGenerate()
	if err != nil {
		return fmt.Errorf("hubnet: load wireguard key: %w", err)
	}
	a.profileID = profileID
	a.wgPrivate = wgPrivate
	if err := a.loadDeviceKey(); err != nil {
		a.logger.Warn("device key unavailable; connecting as a plain key", slog.String("err", err.Error()))
	}
	// Agent-local port grants are retired; clear the ones stored before.
	if err := os.Remove(filepath.Join(a.config.StateDir, retiredPortsFile)); err == nil {
		a.logger.Info("cleared retired port grants")
	} else if !errors.Is(err, os.ErrNotExist) {
		a.logger.Warn("clear retired port grants", slog.String("err", err.Error()))
	}

	prof, err := profile.New(profileID)
	if err != nil {
		return fmt.Errorf("hubnet: build profile: %w", err)
	}
	pub, err := wireGuardPublicKey(wgPrivate)
	if err != nil {
		return fmt.Errorf("hubnet: derive wireguard public key: %w", err)
	}
	prof.SetWireGuardPublicKey(pub)
	a.mu.Lock()
	a.profile = prof
	a.mu.Unlock()

	if err := a.prepareEnforcement(); err != nil {
		// On non-Linux platforms without an injected backend the platform
		// constructor returns ErrPlatformUnsupported. The agent still runs,
		// advertising no enforcement capability; ConnectToShare/AuthorizeFlow
		// surface the missing backend when invoked. This matches the
		// network-agent spec "Unsupported platforms fail safely".
		if !errors.Is(err, enforcement.ErrPlatformUnsupported) {
			return fmt.Errorf("hubnet: prepare enforcement: %w", err)
		}
		a.logger.Warn("enforcement backend unsupported on this platform; per-resource authorization unavailable", slog.String("err", err.Error()))
	}

	key, err := profileID.PublicKeyBase64()
	if err != nil {
		return fmt.Errorf("hubnet: read profile public key: %w", err)
	}
	registrar, err := profile.NewRegistrar(profile.RegistrarOptions{
		Profile:     prof,
		Key:         key,
		MemberKey:   a.deviceMemberKey(),
		Name:        "hub-net",
		BindingKind: a.bindingKind,
	})
	if err != nil {
		return fmt.Errorf("hubnet: build registrar: %w", err)
	}
	a.registrar = registrar

	attestHandler, err := ipc.NewAttestHandler(ipc.AttestHandlerOptions{
		Agent:          a.profileID,
		Policy:         ipc.DefaultTargetPolicy(),
		AttestationTTL: a.config.AttestationTTL,
	})
	if err != nil {
		return fmt.Errorf("hubnet: build ipc handler: %w", err)
	}
	server, err := ipc.NewServer(ipc.ServerOptions{
		SocketPath: a.config.AgentSocketPath,
		Handler:    attestHandler,
		Logger:     a.logger,
	})
	if err != nil {
		return fmt.Errorf("hubnet: build ipc server: %w", err)
	}
	a.ipcServer = server
	return nil
}

// Run starts the agent and blocks until ctx is cancelled or a fatal error
// occurs. The Hub service connection and IPC server are brought up here; the
// concrete RPC handler registration lands in HN-309.
func (a *Agent) Run(ctx context.Context) (err error) {
	defer func() {
		// The supervisor only records the error for `hub-net list`; log it
		// so a session that never comes up is visible in the daemon log.
		if err != nil && !errors.Is(err, context.Canceled) {
			a.logger.Error("hub session stopped", slog.String("hub", fmt.Sprint(a.config.HubAddress)), slog.String("err", err.Error()))
		}
	}()
	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		return errors.New("hubnet: already started")
	}
	runCtx, cancel := context.WithCancel(ctx)
	a.cancelRun = cancel
	a.started = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.started = false
		a.cancelRun = nil
		a.mu.Unlock()
	}()

	if a.profile == nil {
		if err := a.Prepare(runCtx); err != nil {
			cancel()
			return err
		}
	}
	// HN-301 will issue real profile registration; the scaffold marks intent.
	a.profile.BeginRegistration()
	defer a.profile.SetState(profile.StateUnregistered)

	svc, err := hubconn.New(hubconn.Options{
		Identity:    a.profileID,
		Address:     a.config.HubAddress,
		Name:        "hub-net",
		HubKeysPath: hubservice.HubKeysPathFor(a.config.IdentityPath),
		Device:      a.deviceKey,
		NetworkOptions: network.Options{
			AgentSocket: a.config.AgentSocketPath,
		},
		OnConnect: func(sender *channelgo.Sender) {
			if a.registrar == nil {
				return
			}
			if err := a.registrar.Register(runCtx, sender); err != nil {
				a.resolver.Deactivate()
				a.logger.Error("profile register failed", slog.String("err", err.Error()))
				return
			}
			go a.watchNetUsers(runCtx, sender)
			go a.watchRevokedDevices(runCtx, sender)
			if err := a.configureInterface(); err != nil {
				a.resolver.Deactivate()
				a.profile.SetState(profile.StateUnregistered)
				a.logger.Error("wireguard interface setup failed", slog.String("err", err.Error()))
				return
			}
			if err := a.allowHubControl(); err != nil {
				a.logger.Error("hub-server overlay access failed", slog.String("err", err.Error()))
			}
			a.mu.Lock()
			profiles := a.memberProfiles
			a.mu.Unlock()
			a.syncMemberPeers(runCtx, profiles)
			if a.links != nil {
				// A recreated interface lost the linked peers
				a.links.Reapply()
				go a.watchLinks(runCtx, sender)
			}
			if a.activateNetwork != nil {
				if err := a.activateNetwork(); err != nil {
					_ = a.stopInterface()
					a.resolver.Deactivate()
					a.profile.SetState(profile.StateUnregistered)
					a.logger.Error("network translation setup failed", slog.String("err", err.Error()))
					return
				}
			}
			if a.production {
				// Split DNS only adds .hub.invalid names. Hosts without
				// systemd-resolved (containers, minimal servers) still get the
				// tunnel and reach peers by address.
				if err := a.dnsServer.Install(runCtx); err != nil {
					a.logger.Warn("split DNS unavailable; overlay names will not resolve", slog.String("err", err.Error()))
				}
			}
			a.resolver.Activate()
			// Off the channel loop: the advertisement waits for hub-server's
			// answer, which this loop delivers.
			go func() {
				if err := a.restoreGateway(runCtx, sender); err != nil {
					a.logger.Error("gateway restore failed", slog.String("err", err.Error()))
				}
			}()
			if a.onConnect != nil {
				a.onConnect(runCtx, sender)
			}
			go a.watchNodeEndpoint(runCtx, sender)
		},
	})
	if err != nil {
		return fmt.Errorf("hubnet: build hub service: %w", err)
	}
	for _, share := range a.initialShares {
		svc.Share(share.Name, network.Protocol(share.Protocol), share.Host, share.Port,
			&network.Policy{Mode: network.PolicyHub})
	}
	controller, err := control.New(control.Options{
		Profile: a.profile,
		Adapter: a.adapter,
	})
	if err != nil {
		return fmt.Errorf("hubnet: build control API: %w", err)
	}
	if err := controller.Register(svc); err != nil {
		return fmt.Errorf("hubnet: register control API: %w", err)
	}
	// Invitations name the node this agent is registered with, so they follow
	// hub-server's hub/net/node setting like the node client does.
	if err := invitation.RegisterInviteService(svc, a.profileID, a.currentNodeEndpoint, func() bool {
		return a.nodeClient != nil && a.nodeClient.Online()
	}); err != nil {
		return fmt.Errorf("hubnet: register invitation API: %w", err)
	}
	links, err := a.newLinkManager()
	if err != nil {
		return fmt.Errorf("hubnet: peer links: %w", err)
	}
	a.links = links
	go links.Run(runCtx)
	nodeClient, err := nodeclient.New(nodeclient.Options{
		Endpoint: a.currentNodeEndpoint,
		Identity: a.profileID,
		Logger:   a.logger,
		Links:    links.Handle,
		Presence: links.PresenceChanged,
		// The inviter's bootstrap listener owns one UDP socket: it sends the
		// invitation probe (so the node-observed endpoint is the listener
		// address) and accepts framed signed requests from joiners. Declared
		// candidates mirror the same address for peers that prefer them.
		Candidates: func() []protocol.Candidate {
			listener := a.bootstrapListener
			if listener == nil {
				return nil
			}
			address, ok := listener.Addr().(*net.UDPAddr)
			if !ok {
				return nil
			}
			return []protocol.Candidate{{
				CandidateID: "inviter-bootstrap",
				Kind:        "host",
				Transport:   "udp",
				Address:     a.advertisedAddress(address.IP),
				Port:        uint16(address.Port),
				Priority:    100,
			}}
		},
		Probe: func(ctx context.Context, endpoint string, probe nodeprotocol.InvitationUDPProbe, expectedTicketID string) error {
			listener := a.bootstrapListener
			if listener == nil {
				return errors.New("hubnet: bootstrap listener unavailable")
			}
			return listener.Probe(ctx, endpoint, probe, expectedTicketID)
		},
		Pending: func(tokenDigest, joinerKey string) {
			if a.inviter != nil {
				a.inviter.Expect(tokenDigest, joinerKey)
			}
		},
		Bootstrap: func(event nodeclient.BootstrapEvent) {
			a.logger.Info("inviter bootstrap rendezvous",
				slog.String("joiner", event.JoinerKey),
				slog.String("transaction", event.TransactionID),
				slog.String("session", event.SessionID),
				slog.Int("candidates", len(event.Candidates)),
				slog.String("observed", event.Observed.Address),
			)
		},
	})
	if err != nil {
		a.logger.Warn("node registration client unavailable", slog.String("err", err.Error()))
	} else {
		a.nodeClient = nodeClient
	}
	wgPublicKey, err := wireGuardPublicKey(a.wgPrivate)
	if err != nil {
		a.logger.Warn("inviter wireguard key unavailable", slog.String("err", err.Error()))
	} else if inviter, err := invitation.NewInviter(invitation.InviterOptions{
		MemberPeer:   a.memberPeerAddresses,
		Identity:     a.profileID,
		WireGuardKey: wgPublicKey,
		Adapter:      a.adapter,
		// The signed response carries the bootstrap listener endpoint so a
		// joiner can retry a direct exchange without re-reading the paired
		// session. The WireGuard handshake itself uses the adapter's listen
		// port on the same address.
		Endpoints: func() []protocol.BootstrapEndpoint {
			listener := a.bootstrapListener
			if listener == nil {
				return nil
			}
			address, ok := listener.Addr().(*net.UDPAddr)
			if !ok {
				return nil
			}
			port := uint16(wireguard.DefaultPort)
			if state, up := a.adapter.State(); up && state.ListenPort != 0 {
				port = state.ListenPort
			}
			return []protocol.BootstrapEndpoint{{
				Address: a.advertisedAddress(address.IP), Port: port, Transport: "udp",
			}}
		},
		HubProHost: func() string {
			if a.netUsers == nil {
				return ""
			}
			for _, value := range a.ownAddresses() {
				if parsed, err := netip.ParseAddr(value); err == nil && parsed.Is4() {
					return parsed.String()
				}
			}
			return ""
		},
	}); err != nil {
		a.logger.Warn("inviter bootstrap handler unavailable", slog.String("err", err.Error()))
	} else {
		a.inviter = inviter
		defer func() {
			a.inviter.CloseAll(context.Background())
		}()
	}
	if a.inviter != nil {
		listener, err := invitation.NewListener(invitation.ListenerOptions{
			Inviter: a.inviter,
			Address: a.config.BootstrapListenAddress,
			Logger:  a.logger,
		})
		if err != nil {
			a.logger.Warn("inviter bootstrap listener unavailable", slog.String("err", err.Error()))
		} else {
			a.bootstrapListener = listener
			defer listener.Close()
		}
	}
	if err := netapi.Register(svc, netapi.Options{
		Registry: a.netUsers,
		AgentID:  func() string { key, _ := a.profileID.PublicKeyBase64(); return key },
		Self:     a.isSelf,
		AgentAddresses: func() (string, string) {
			addresses := a.ownAddresses()
			var v4, v6 string
			for _, value := range addresses {
				if parsed, err := netip.ParseAddr(value); err == nil {
					if parsed.Is4() {
						v4 = value
					} else {
						v6 = value
					}
				}
			}
			return v4, v6
		},
		NodeOnline: func() bool {
			if a.nodeClient == nil {
				return false
			}
			return a.nodeClient.Online()
		},
		VPN: func() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.gatewayActive },
		PeerUsage: func() []netapi.PeerUsage {
			if a.connections == nil {
				return nil
			}
			peers := a.connections.Peers()
			out := make([]netapi.PeerUsage, 0, len(peers))
			for _, peer := range peers {
				out = append(out, netapi.PeerUsage{WireGuardKey: base64.StdEncoding.EncodeToString(peer.PublicKey), LastUsed: peer.LastUsed, Online: true})
			}
			return out
		},
		RevokePeer: func(user protocol.AgentProfile) error {
			raw, err := base64.StdEncoding.DecodeString(user.WireGuardKey)
			if err != nil {
				return err
			}
			if a.connections != nil {
				err = a.connections.Remove(raw)
			} else {
				err = a.adapter.RemovePeer(raw)
			}
			if err != nil || a.enforcementMgr == nil {
				return err
			}
			var sources []netip.Addr
			for _, prefix := range overlayPrefixes(user.OverlayAddresses) {
				sources = append(sources, prefix.Addr())
			}
			a.mu.Lock()
			sources = append(sources, a.peerSources[user.WireGuardKey]...)
			a.mu.Unlock()
			return a.enforcementMgr.RevokeSources(sources)
		},
	}); err != nil {
		return fmt.Errorf("hubnet: register network API: %w", err)
	}
	a.control = controller
	a.mu.Lock()
	a.hubService = svc
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.hubService == svc {
			a.hubService = nil
		}
		a.mu.Unlock()
	}()
	defer svc.Stop()
	defer func() {
		if err := a.disableGateway(context.Background(), false); err != nil {
			a.logger.Error("gateway teardown failed", slog.String("err", err.Error()))
		}
	}()
	defer func() {
		if err := a.stopInterface(); err != nil {
			a.logger.Error("wireguard interface teardown failed", slog.String("err", err.Error()))
		}
	}()
	var dnsErr error
	if a.production {
		dnsErr = a.dnsServer.StartUnconfigured(runCtx, a.config.DNSListenAddress)
	} else {
		dnsErr = a.dnsServer.Start(runCtx, a.config.DNSListenAddress)
	}
	if dnsErr != nil {
		return fmt.Errorf("hubnet: start dns resolver: %w", dnsErr)
	}
	defer func() {
		if err := a.dnsServer.Close(context.Background()); err != nil {
			a.logger.Error("dns resolver teardown failed", slog.String("err", err.Error()))
		}
	}()
	// Bring up machine-local IPC before opening the Hub connection. hub-server
	// challenges this socket while processing hub/net/bind, so
	// starting Hub first creates a reconnect-sensitive registration race.
	ipcCtx, ipcCancel := context.WithCancel(runCtx)
	a.mu.Lock()
	a.ipcCancel = ipcCancel
	a.mu.Unlock()
	ipcErrs := a.ipcServer.Start(ipcCtx)
	if a.nodeClient != nil {
		go func() {
			if err := a.nodeClient.Run(runCtx); err != nil && runCtx.Err() == nil {
				a.logger.Error("node registration client stopped", slog.String("err", err.Error()))
			}
		}()
	}
	if a.bootstrapListener != nil {
		go func() {
			if err := a.bootstrapListener.Run(runCtx); err != nil && runCtx.Err() == nil {
				a.logger.Error("inviter bootstrap listener stopped", slog.String("err", err.Error()))
			}
		}()
	}
	if a.inviter != nil {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-ticker.C:
					a.inviter.Sweep(runCtx)
				}
			}
		}()
	}
	if a.bindingKind == protocol.LocalAgentBindingJoin && a.knownAddress.IsValid() {
		// hub-server is reachable only through the overlay; without the tunnel
		// the first connect (and so the interface setup in OnConnect) never
		// happens after a restart.
		if err := a.bringUpInterface(a.knownAddress, a.knownIPv6); err != nil {
			a.logger.Error("wireguard interface setup failed", slog.String("err", err.Error()))
		}
	}
	if err := svc.Start(); err != nil {
		ipcCancel()
		<-ipcErrs
		return fmt.Errorf("hubnet: start hub service: %w", err)
	}
	select {
	case <-runCtx.Done():
		ipcCancel()
		<-ipcErrs
		return runCtx.Err()
	case err := <-ipcErrs:
		if err != nil {
			return fmt.Errorf("hubnet: ipc server: %w", err)
		}
	}

	<-runCtx.Done()
	ipcCancel()
	<-ipcErrs
	return runCtx.Err()
}

func (a *Agent) watchNetUsers(ctx context.Context, sender *channelgo.Sender) {
	values := sender.Values("network/agents/list", nil)
	defer values.Return()
	for {
		item, err := values.Next(ctx)
		if err != nil || item.Done {
			return
		}
		encoded, err := json.Marshal(item.Value)
		if err != nil {
			continue
		}
		var profiles []protocol.AgentProfile
		if json.Unmarshal(encoded, &profiles) != nil {
			continue
		}
		a.netUsers.Replace(profiles)
		a.mu.Lock()
		a.memberProfiles = profiles
		for _, profile := range profiles {
			for _, prefix := range overlayPrefixes(profile.OverlayAddresses) {
				a.rememberPeerSourceLocked(profile.WireGuardKey, prefix.Addr())
			}
		}
		a.mu.Unlock()
		a.syncMemberPeers(ctx, profiles)
	}
}

// syncMemberPeers keeps one WireGuard peer per network member on the hub
// host's agent. Members reach hub-server and shared ports through this host with
// their permanent overlay addresses; a member still inside its bootstrap
// window also keeps the temporary addresses (the inviter merges them).
// Joined members' agents only see themselves and do nothing here.
func (a *Agent) syncMemberPeers(ctx context.Context, profiles []protocol.AgentProfile) {
	if a.bindingKind != "" && a.bindingKind != protocol.LocalAgentBindingMachine {
		return
	}
	if _, up := a.adapter.State(); !up {
		return
	}
	desired := make(map[string][]netip.Prefix)
	for _, profile := range profiles {
		if profile.Key == "" || a.isSelf(profile.Key) || profile.WireGuardKey == "" {
			continue
		}
		if !a.netUsers.Exists(profile.Key) {
			continue // revoked with net/revoke
		}
		if a.isRevokedPeer(profile.Key, profile.WireGuardKey) {
			continue // revoked device
		}
		key, err := base64.StdEncoding.DecodeString(profile.WireGuardKey)
		if err != nil || len(key) != 32 {
			continue
		}
		prefixes := overlayPrefixes(profile.OverlayAddresses)
		if len(prefixes) == 0 {
			continue
		}
		desired[profile.WireGuardKey] = prefixes
		if a.inviter != nil {
			err := a.inviter.UpdateJoinerAllowedIPs(ctx, profile.Key, prefixes)
			if err == nil {
				continue
			}
			if !errors.Is(err, invitation.ErrBootstrapReplay) {
				a.logger.Error("update joiner peer", slog.String("user", profile.Key), slog.String("err", err.Error()))
			}
		}
		if err := a.adapter.AddPeer(wireguard.PeerConfig{PublicKey: key, AllowedIPs: prefixes}); err != nil {
			a.logger.Error("add member peer", slog.String("user", profile.Key), slog.String("err", err.Error()))
		}
	}
	a.mu.Lock()
	previous := a.memberPeers
	a.memberPeers = desired
	a.mu.Unlock()
	for wireGuardKey := range previous {
		if _, ok := desired[wireGuardKey]; ok {
			continue
		}
		if key, err := base64.StdEncoding.DecodeString(wireGuardKey); err == nil {
			_ = a.adapter.RemovePeer(key)
		}
	}
}

// loadDeviceKey loads the device key the agent's service key is certified
// with: the configured file, else (production only) the hub-service lookup.
func (a *Agent) loadDeviceKey() error {
	var (
		key *hubservice.DeviceKey
		err error
	)
	switch {
	case a.config.DeviceKeyPath != "":
		key, err = hubservice.LoadDeviceKeyFile(a.config.DeviceKeyPath)
	case a.production:
		key, err = hubservice.LoadDeviceKey()
	default:
		return nil
	}
	if err != nil {
		return err
	}
	a.deviceKey = key
	return nil
}

// DeviceID is this agent's device id, "" when it connects as a plain key.
func (a *Agent) DeviceID() string {
	if a.deviceKey == nil {
		return ""
	}
	return a.deviceKey.ID()
}

// deviceMemberKey is the key hubs list this agent's membership under when its
// connection is device-attached (Docs/Devices/protocol.md section 10).
func (a *Agent) deviceMemberKey() string {
	if id := a.DeviceID(); id != "" {
		return "device:" + id
	}
	return ""
}

// isSelf reports whether a member key is this agent's: its service key
// (legacy hubs, or an unapproved device) or its device member key.
func (a *Agent) isSelf(key string) bool {
	if key == "" {
		return false
	}
	if device := a.deviceMemberKey(); device != "" && key == device {
		return true
	}
	self, _ := a.profileID.PublicKeyBase64()
	return key == self
}

// ownAddresses are this agent's overlay addresses from the member list.
func (a *Agent) ownAddresses() []string {
	if device := a.deviceMemberKey(); device != "" {
		if addresses := a.netUsers.Addresses(device); len(addresses) > 0 {
			return addresses
		}
	}
	self, _ := a.profileID.PublicKeyBase64()
	return a.netUsers.Addresses(self)
}

// RevokedDevice is one entry of the network/devices/revoked stream.
type RevokedDevice struct {
	Device        string   `json:"device"`
	WireGuardKeys []string `json:"wireGuardKeys"`
	At            string   `json:"at"`
}

// watchRevokedDevices mirrors network/devices/revoked, the full list of
// revoked devices of this hub (Docs/Devices/protocol.md section 10). Hubs
// without the stream end it at once.
func (a *Agent) watchRevokedDevices(ctx context.Context, sender *channelgo.Sender) {
	values := sender.Values("network/devices/revoked", nil)
	defer values.Return()
	for {
		item, err := values.Next(ctx)
		if err != nil || item.Done {
			return
		}
		encoded, err := json.Marshal(item.Value)
		if err != nil {
			continue
		}
		var revoked []RevokedDevice
		if json.Unmarshal(encoded, &revoked) != nil {
			continue
		}
		a.ApplyRevokedDevices(revoked)
	}
}

// ApplyRevokedDevices drops the WireGuard peers of revoked devices with every
// firewall rule sourced from their overlay addresses, and refuses them as
// peers from then on.
func (a *Agent) ApplyRevokedDevices(revoked []RevokedDevice) {
	peers := map[string]struct{}{}
	members := map[string]struct{}{}
	for _, device := range revoked {
		if device.Device != "" {
			members["device:"+device.Device] = struct{}{}
		}
		for _, key := range device.WireGuardKeys {
			if key != "" {
				peers[key] = struct{}{}
			}
		}
	}
	remove := make(map[string]struct{}, len(peers))
	for key := range peers {
		remove[key] = struct{}{}
	}
	a.mu.Lock()
	a.revokedPeers = peers
	a.revokedMembers = members
	profiles := a.memberProfiles
	// syncMemberPeers reads the previous map unlocked, so replace it.
	kept := make(map[string][]netip.Prefix, len(a.memberPeers))
	for key, prefixes := range a.memberPeers {
		if _, ok := peers[key]; !ok {
			kept[key] = prefixes
		}
	}
	a.memberPeers = kept
	a.mu.Unlock()

	var sources []netip.Addr
	for _, profile := range profiles {
		if !a.isRevokedPeer(profile.Key, profile.WireGuardKey) {
			continue
		}
		if profile.WireGuardKey != "" {
			remove[profile.WireGuardKey] = struct{}{}
		}
		for _, prefix := range overlayPrefixes(profile.OverlayAddresses) {
			sources = append(sources, prefix.Addr())
		}
	}
	a.mu.Lock()
	for key := range remove {
		sources = append(sources, a.peerSources[key]...)
	}
	a.mu.Unlock()
	for key := range remove {
		raw, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(raw) != 32 {
			continue
		}
		if a.connections != nil {
			_ = a.connections.Remove(raw)
		}
		_ = a.adapter.RemovePeer(raw)
	}
	if a.enforcementMgr != nil {
		if err := a.enforcementMgr.RevokeSources(sources); err != nil {
			a.logger.Error("revoke device firewall rules", slog.String("err", err.Error()))
		}
	}
}

func (a *Agent) rememberPeerSourceLocked(wireGuardKey string, address netip.Addr) {
	if wireGuardKey == "" || !address.IsValid() {
		return
	}
	if a.peerSources == nil {
		a.peerSources = map[string][]netip.Addr{}
	}
	for _, known := range a.peerSources[wireGuardKey] {
		if known == address {
			return
		}
	}
	a.peerSources[wireGuardKey] = append(a.peerSources[wireGuardKey], address)
}

// isRevokedPeer reports whether a member key or WireGuard key belongs to a
// revoked device.
func (a *Agent) isRevokedPeer(memberKey, wireGuardKey string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.revokedMembers[memberKey]; ok && memberKey != "" {
		return true
	}
	_, ok := a.revokedPeers[wireGuardKey]
	return ok && wireGuardKey != ""
}

// memberPeerAddresses returns a member's permanent overlay prefixes by
// WireGuard key, for the inviter to keep when a bootstrap peer closes.
func (a *Agent) memberPeerAddresses(wireGuardKey []byte) []netip.Prefix {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.memberPeers[base64.StdEncoding.EncodeToString(wireGuardKey)]
}

// overlayPrefixes converts overlay addresses into host prefixes.
func overlayPrefixes(addresses []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(addresses))
	for _, value := range addresses {
		if address, err := netip.ParseAddr(value); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	return prefixes
}

// advertisedAddress is the address joiners are told to use for this inviter:
// the configured AdvertiseAddress, else the listener's own address.
func (a *Agent) advertisedAddress(listener net.IP) string {
	if a.config.AdvertiseAddress != "" {
		return a.config.AdvertiseAddress
	}
	return listener.String()
}

// allowHubControl opens hub-server's port on this host's overlay address when
// this agent serves the hub running on the same machine. Members and joiners
// reach hub-server only through the overlay; everything else stays fail-closed.
func (a *Agent) allowHubControl() error {
	if a.enforcementMgr == nil || (a.bindingKind != "" && a.bindingKind != protocol.LocalAgentBindingMachine) {
		return nil
	}
	address := a.profile.Snapshot().OverlayAddress
	if address == "" {
		return nil
	}
	return a.enforcementMgr.AllowControl([]string{address}, hubPort(a.config.HubAddress))
}

// hubPort extracts the port from a hub address (port number, "host:port" or
// ws:// URL), defaulting to hub-server's 1997.
func hubPort(address any) uint16 {
	switch value := address.(type) {
	case int:
		return uint16(value)
	case float64:
		return uint16(value)
	case string:
		if parsed, err := url.Parse(value); err == nil && parsed.Port() != "" {
			value = parsed.Host
		}
		if _, port, err := net.SplitHostPort(value); err == nil {
			if number, err := strconv.ParseUint(port, 10, 16); err == nil && number != 0 {
				return uint16(number)
			}
		}
	}
	return config.DefaultHubPort
}

// currentNodeEndpoint returns the hub-server advertised hub-net-node endpoint,
// falling back to the locally configured node endpoints. Empty disables node
// registration.
func (a *Agent) currentNodeEndpoint() string {
	a.mu.Lock()
	subscribed := a.nodeEndpoint
	a.mu.Unlock()
	if subscribed != "" {
		return subscribed
	}
	if a.control == nil {
		return ""
	}
	for _, endpoint := range a.control.NodeConfig().Endpoints {
		if strings.TrimSpace(endpoint) != "" {
			return strings.TrimSpace(endpoint)
		}
	}
	return ""
}

// watchNodeEndpoint mirrors hub-server's hub/net/node stream so node registrations
// follow operator changes to the configured rendezvous endpoint.
func (a *Agent) watchNodeEndpoint(ctx context.Context, sender *channelgo.Sender) {
	values := sender.Values("hub/net/node", nil)
	defer values.Return()
	for {
		item, err := values.Next(ctx)
		if err != nil || item.Done {
			return
		}
		encoded, err := json.Marshal(item.Value)
		if err != nil {
			continue
		}
		var endpoint string
		if json.Unmarshal(encoded, &endpoint) != nil {
			continue
		}
		a.mu.Lock()
		a.nodeEndpoint = strings.TrimSpace(endpoint)
		a.mu.Unlock()
	}
}

// OpenShare publishes one daemon-owned loopback share.
func (a *Agent) OpenShare(ctx context.Context, entry publications.Entry) error {
	a.mu.Lock()
	service := a.hubService
	a.mu.Unlock()
	if service == nil {
		return errors.New("hubnet: Hub session not connected")
	}
	_, err := service.PublishShare(ctx, entry.Name, network.Protocol(entry.Protocol),
		entry.Host, entry.Port, &network.Policy{Mode: network.PolicyHub})
	return err
}

// CloseShare removes one daemon-owned share. Missing desired state is idempotent.
func (a *Agent) CloseShare(ctx context.Context, name string) error {
	a.mu.Lock()
	service := a.hubService
	a.mu.Unlock()
	if service == nil {
		return errors.New("hubnet: Hub session not connected")
	}
	if _, found := service.Network().DeclaredShare(name); !found {
		return nil
	}
	_, err := service.RemoveShare(ctx, name)
	return err
}

// EnableGateway starts contained forwarding/NAT before publishing capability.
func (a *Agent) EnableGateway(ctx context.Context) error {
	a.mu.Lock()
	a.gatewayAllowed = true
	service := a.hubService
	a.mu.Unlock()
	if service == nil || service.Sender() == nil {
		return nil
	}
	if err := a.restoreGateway(ctx, service.Sender()); err != nil {
		a.mu.Lock()
		a.gatewayAllowed = false
		a.mu.Unlock()
		return err
	}
	return nil
}

// DisableGateway removes Hub advertisement first, then tears down firewall,
// NAT, forwarding, and tracked flows.
func (a *Agent) DisableGateway(ctx context.Context) error {
	a.mu.Lock()
	a.gatewayAllowed = false
	a.mu.Unlock()
	return a.disableGateway(ctx, true)
}

func (a *Agent) restoreGateway(ctx context.Context, sender *channelgo.Sender) error {
	a.gatewayMu.Lock()
	defer a.gatewayMu.Unlock()
	a.mu.Lock()
	if !a.gatewayAllowed || a.gatewayActive {
		a.mu.Unlock()
		return nil
	}
	backend := a.gatewayBackend
	interfaceName := a.interfaceName
	a.mu.Unlock()
	if backend == nil {
		return gateway.ErrPlatformUnsupported
	}
	if err := backend.Enable(gateway.DefaultConfig(interfaceName)); err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		_ = backend.Disable()
		return errors.New("gateway: hostname unavailable")
	}
	capability := protocol.GatewayCapability{
		Version: 1, Capability: "internet-gateway-v1",
		IPv4: true, IPv6: true, DNS: true,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if _, err := sendWithin(ctx, sender, gatewayRequestTimeout, "network/gateway/advertise", map[string]any{
		"capability": capability,
		"endpoint":   fmt.Sprintf("%s:%d", hostname, wireguard.DefaultPort),
	}); err != nil {
		_ = backend.Disable()
		if errors.Is(err, errHubDidNotAnswer) {
			return fmt.Errorf("gateway: %w (the hub's owner may need to allow this device Hub Network: Provide Gateway)", err)
		}
		return fmt.Errorf("gateway: %w", err)
	}
	a.mu.Lock()
	a.gatewayActive = true
	a.mu.Unlock()
	return nil
}

// gatewayRequestTimeout bounds the gateway calls to hub-server. A hub that
// never answers (an older hub, or one holding the call for the owner's
// approval) must not hold the daemon's command lock.
const gatewayRequestTimeout = 15 * time.Second

var errHubDidNotAnswer = errors.New("the hub did not answer")

// sendWithin sends one request and waits for its answer for at most timeout,
// cancelling it after. Never call it on the channel's own loop (OnConnect):
// the answer is read there, so it would always time out.
func sendWithin(ctx context.Context, sender *channelgo.Sender, timeout time.Duration, path string, body any) (any, error) {
	request := sender.Request(path, body)
	type answer struct {
		value any
		err   error
	}
	answered := make(chan answer, 1)
	go func() {
		value, err := request.Wait()
		answered <- answer{value, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-answered:
		return result.value, result.err
	case <-timer.C:
		request.Cancel()
		return nil, fmt.Errorf("%s: %w within %s", path, errHubDidNotAnswer, timeout)
	case <-ctx.Done():
		request.Cancel()
		return nil, ctx.Err()
	}
}

func (a *Agent) disableGateway(ctx context.Context, advertise bool) error {
	a.gatewayMu.Lock()
	defer a.gatewayMu.Unlock()
	a.mu.Lock()
	active := a.gatewayActive
	backend := a.gatewayBackend
	service := a.hubService
	a.gatewayActive = false
	a.mu.Unlock()
	if !active {
		return nil
	}
	var result error
	if advertise && service != nil && service.Sender() != nil {
		_, err := sendWithin(ctx, service.Sender(), gatewayRequestTimeout, "network/gateway/remove", map[string]string{"reason": "provider_disabled"})
		result = errors.Join(result, err)
	}
	if backend != nil {
		result = errors.Join(result, backend.Disable())
	}
	return result
}

// configureInterface applies the Hub-assigned overlay address only after a
// successful registration. Reconnect replaces the old interface atomically
// from the agent's perspective: old state is removed before the new address
// is advertised locally, and failed setup leaves no tunnel behind.
func (a *Agent) configureInterface() error {
	snapshot := a.profile.Snapshot()
	if snapshot.OverlayAddress == "" {
		return errors.New("hubnet: registration returned no overlay address")
	}
	address, err := netip.ParseAddr(snapshot.OverlayAddress)
	if err != nil {
		return fmt.Errorf("hubnet: invalid overlay address %q: %w", snapshot.OverlayAddress, err)
	}
	if !wireguard.IPv4OverlayPrefix.Contains(address) && !wireguard.IPv6OverlayPrefix.Contains(address) {
		return fmt.Errorf("hubnet: overlay address outside reserved ranges: %s", address)
	}
	var ipv6 netip.Addr
	if snapshot.OverlayIPv6 != "" {
		ipv6, err = netip.ParseAddr(snapshot.OverlayIPv6)
		if err != nil || !wireguard.IPv6OverlayPrefix.Contains(ipv6) {
			return fmt.Errorf("hubnet: invalid IPv6 overlay address %q", snapshot.OverlayIPv6)
		}
	}
	if err := a.bringUpInterface(address, ipv6); err != nil {
		return err
	}
	if a.onRegistered != nil {
		a.onRegistered(address.String(), snapshot.OverlayIPv6)
	}
	return nil
}

// bringUpInterface starts the WireGuard interface with the overlay addresses
// and the initial peers. A running interface with the same addresses is left
// alone: a joined member's Hub connection runs through it, and tearing it
// down on every reconnect would cut that connection.
func (a *Agent) bringUpInterface(address, ipv6 netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.networkUp && a.interfaceAddress == address && a.interfaceIPv6 == ipv6 {
		return nil
	}
	if a.networkUp {
		if err := a.adapter.Down(); err != nil {
			return fmt.Errorf("hubnet: replace wireguard interface: %w", err)
		}
		a.networkUp = false
	}
	config := wireguard.InterfaceConfig{
		Name:        a.interfaceName,
		PrivateKey:  append([]byte(nil), a.wgPrivate...),
		Address:     address,
		AddressIPv6: ipv6,
		ListenPort:  wireguard.DefaultPort,
		Peers:       append([]wireguard.PeerConfig(nil), a.initialPeers...),
	}
	if err := a.adapter.Up(config); err != nil {
		_ = a.adapter.Down()
		return fmt.Errorf("hubnet: start wireguard interface: %w", err)
	}
	a.networkUp = true
	a.interfaceAddress = address
	a.interfaceIPv6 = ipv6
	return nil
}

// parseOptionalAddr parses an address, returning the zero Addr when empty or
// invalid.
func parseOptionalAddr(value string) netip.Addr {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return address
}

func (a *Agent) stopInterface() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.networkUp {
		return nil
	}
	err := a.adapter.Down()
	a.networkUp = false
	return err
}

// Connected reports whether the session is bound at its Hub.
func (a *Agent) Connected() bool {
	a.mu.Lock()
	prof := a.profile
	a.mu.Unlock()
	return prof != nil && prof.Snapshot().State == profile.StateRegistered
}

// OverlayAddress reports the IPv4 overlay address the Hub assigned this
// session, empty before it registers.
func (a *Agent) OverlayAddress() string {
	a.mu.Lock()
	prof := a.profile
	a.mu.Unlock()
	if prof == nil {
		return ""
	}
	return prof.Snapshot().OverlayAddress
}

// OverlayIPv6 reports the IPv6 overlay address the Hub assigned this session,
// empty before it registers or when it assigned none.
func (a *Agent) OverlayIPv6() string {
	a.mu.Lock()
	prof := a.profile
	a.mu.Unlock()
	if prof == nil {
		return ""
	}
	return prof.Snapshot().OverlayIPv6
}

// Shutdown signals Run to stop. Safe to call multiple times.
func (a *Agent) Shutdown() {
	a.mu.Lock()
	cancel := a.cancelRun
	ipcCancel := a.ipcCancel
	a.mu.Unlock()
	if ipcCancel != nil {
		ipcCancel()
	}
	if cancel != nil {
		cancel()
	}
}

// RotateWireGuardKey replaces the persisted WireGuard private key and updates
// the in-memory profile. The next registrar.Register call binds the new
// public key to the same profile identity through a fresh short-lived grant;
// established sessions expire as their old grants lapse. The profile identity
// and stable share ownership are untouched.
func (a *Agent) RotateWireGuardKey() error {
	newPrivate, err := a.wgSt.Rotate()
	if err != nil {
		return fmt.Errorf("hubnet: rotate wireguard key: %w", err)
	}
	pub, err := wireGuardPublicKey(newPrivate)
	if err != nil {
		return fmt.Errorf("hubnet: derive rotated wireguard public key: %w", err)
	}
	a.mu.Lock()
	a.wgPrivate = newPrivate
	if a.profile != nil {
		a.profile.RotateWireGuardPublicKey(pub)
	}
	a.mu.Unlock()
	a.logger.Info("wireguard key rotated")
	return nil
}

// wireGuardPublicKey derives the Curve25519 public key from a 32-byte private
// key using crypto/ecdh. WireGuard uses the same Curve25519 scalar
// multiplication, so the derived public key matches wg set private-key output.
func wireGuardPublicKey(privateKey []byte) ([]byte, error) {
	curve := ecdh.X25519()
	key, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

// prepareEnforcement constructs the per-resource enforcement manager from the
// injected backend (Options.EnforcementBackend) or the platform backend. On
// platforms where the platform backend is unavailable and no backend is
// injected, NewPlatformBackend returns ErrPlatformUnsupported and the manager
// stays nil; the agent then fails closed on AuthorizeFlow.
func (a *Agent) prepareEnforcement() error {
	backend := a.enforcementBackend
	if backend == nil {
		// The WireGuard interface name is only meaningful on Linux where the
		// nftables backend anchors rules to it; on other platforms the call
		// fails before the name is consulted.
		platformBackend, err := enforcement.NewPlatformBackend(a.interfaceName)
		if err != nil {
			return err
		}
		backend = platformBackend
		a.enforcementBackend = backend
	}
	manager, err := enforcement.New(backend)
	if err != nil {
		return err
	}
	a.enforcementMgr = manager
	return nil
}

// Enforcement returns the per-resource enforcement manager, or nil when the
// platform backend is unavailable. Exposed so callers (and the test harness)
// can drive Authorize/UpdateGeneration and inspect installed rules.
func (a *Agent) Enforcement() *enforcement.Manager { return a.enforcementMgr }

// Connections returns the connection manager, or nil before the first
// ConnectToShare call (the manager is built lazily once a Hub key is known).
func (a *Agent) Connections() *connection.Manager { return a.connections }

// Profile returns the agent network profile, or nil before Prepare.
func (a *Agent) Profile() *profile.Profile { return a.profile }

// HubService returns the connected Hub service, or nil before Run.
func (a *Agent) HubService() *hubconn.Service { return a.hubService }

// SetResourceGeneration records the trusted authorization generation for a
// resource. The production agent consumes generations from the
// network/resource/generations stream; the test harness injects them directly
// to drive grant verification deterministically.
func (a *Agent) SetResourceGeneration(resourceID string, generation uint64) {
	a.genMu.Lock()
	defer a.genMu.Unlock()
	a.generations[resourceID] = generation
}

func (a *Agent) lookupGeneration(resourceID string) (uint64, bool) {
	a.genMu.RLock()
	defer a.genMu.RUnlock()
	gen, ok := a.generations[resourceID]
	return gen, ok
}

// ensureVerifier builds the grant.Verifier the first time it is needed. The
// trusted Hub signing key is taken from the profile when the Hub echoed it at
// registration; otherwise it is seeded from the first signature-verified grant
// (the grant's signature proves Hub origin, so adopting its hubKey does not
// widen trust). localWireGuardKey comes from the agent's persisted Curve25519
// private key.
func (a *Agent) ensureVerifier(seedHubKey, seedHubNetworkID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.grantVerifier != nil {
		return nil
	}
	snap := a.profile.Snapshot()
	hubKey := snap.HubKey
	if hubKey == "" {
		hubKey = seedHubKey
	}
	hubNetworkID := snap.HubNetworkID
	if hubNetworkID == "" {
		hubNetworkID = seedHubNetworkID
	}
	wgPub := a.profile.WireGuardPublicKey()
	localWireGuardKey := base64.StdEncoding.EncodeToString(wgPub)
	verifier, err := grant.NewVerifier(grant.LocalBinding{
		HubKey:             hubKey,
		HubNetworkID:       hubNetworkID,
		CallerKey:          snap.Key,
		CallerWireGuardKey: localWireGuardKey,
		CallerMemberKey:    a.deviceMemberKey(),
	}, a.lookupGeneration)
	if err != nil {
		return fmt.Errorf("hubnet: build grant verifier: %w", err)
	}
	a.grantVerifier = verifier
	if hubKey != "" || hubNetworkID != "" {
		// Persist whatever we just trusted so subsequent reconnects/verifiers
		// start from the same anchor without needing another grant.
		a.profile.SetHubTrust(hubKey, hubNetworkID)
	}
	return nil
}

// ensureConnectionManager constructs connection.Manager from injected or
// fail-closed default checkers. Requires the verifier, so callers must run
// ensureVerifier first.
func (a *Agent) ensureConnectionManager() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.connections != nil {
		return nil
	}
	if a.grantVerifier == nil {
		return errors.New("hubnet: grant verifier required before connection manager")
	}
	candidates := a.candidateChecker
	if candidates == nil {
		candidates = failClosedCandidateChecker{}
	}
	handshake := a.handshakeChecker
	if handshake == nil {
		handshake = failClosedHandshakeChecker{}
	}
	manager, err := connection.New(connection.Options{
		Adapter:          a.adapter,
		Verifier:         a.grantVerifier,
		CandidateChecker: candidates,
		HandshakeChecker: handshake,
		HandshakeTimeout: a.config.HandshakeTimeout,
		IdleTimeout:      a.config.PeerIdleTimeout,
	})
	if err != nil {
		return fmt.Errorf("hubnet: build connection manager: %w", err)
	}
	a.connections = manager
	return nil
}

// ConnectToShare requests a connection grant from the Hub for the named
// resource, then drives the connection manager to install the authorized
// peer. Candidates are caller-supplied transport metadata (HN-308/HN-400 will
// source them from the rendezvous node); they are never trusted as
// authorization input. The grant is verified once and consumed.
func (a *Agent) ConnectToShare(ctx context.Context, resourceID, preferredProviderID string, candidates []protocol.Candidate) (protocol.ConnectionGrant, error) {
	if a.hubService == nil {
		return protocol.ConnectionGrant{}, errors.New("hubnet: hub service not started")
	}
	sender := a.hubService.Sender()
	if sender == nil {
		return protocol.ConnectionGrant{}, errors.New("hubnet: hub sender not connected")
	}
	snap := a.profile.Snapshot()
	body := map[string]any{
		"callerWireGuardKey": base64.StdEncoding.EncodeToString(snap.WireGuardPubKey),
		"resourceId":         resourceID,
	}
	if preferredProviderID != "" {
		body["preferredProviderId"] = preferredProviderID
	}
	raw, err := sender.Send("network/connection/grant", body)
	if err != nil {
		return protocol.ConnectionGrant{}, fmt.Errorf("hubnet: request grant: %w", err)
	}
	grantValue, err := decodeGrantResponse(raw)
	if err != nil {
		return protocol.ConnectionGrant{}, fmt.Errorf("hubnet: decode grant: %w", err)
	}
	if err := a.ensureVerifier(grantValue.HubKey, grantValue.HubNetworkID); err != nil {
		return protocol.ConnectionGrant{}, err
	}
	if err := a.ensureConnectionManager(); err != nil {
		return protocol.ConnectionGrant{}, err
	}
	if a.isRevokedPeer(grantValue.TargetKey, grantValue.TargetWireGuardKey) {
		return grantValue, errRevokedPeer
	}
	if err := a.connections.Connect(ctx, grantValue, candidates); err != nil {
		return grantValue, fmt.Errorf("hubnet: establish connection: %w", err)
	}
	return grantValue, nil
}

// AuthorizeFlow installs the per-resource transport rule for a verified grant
// on the target side. The caller MUST have verified the grant signature
// independently (Hub signature is the proof of authorization); this method
// only enforces the bound fields. Returns ErrPlatformUnsupported-shaped errors
// when no enforcement backend is configured.
func (a *Agent) AuthorizeFlow(grantValue protocol.ConnectionGrant) error {
	if a.enforcementMgr == nil {
		return enforcement.ErrPlatformUnsupported
	}
	if a.isRevokedPeer(grantValue.CallerKey, grantValue.CallerWireGuardKey) {
		return errRevokedPeer
	}
	if source, err := netip.ParseAddr(grantValue.CallerAddress); err == nil {
		a.mu.Lock()
		a.rememberPeerSourceLocked(grantValue.CallerWireGuardKey, source)
		a.mu.Unlock()
	}
	return a.enforcementMgr.Authorize(grantValue)
}

// retiredPortsFile held agent-local port grants, retired in favour of
// hub-signed connection grants.
const retiredPortsFile = "ports.json"

// errRevokedPeer refuses a grant whose other end is a revoked device.
var errRevokedPeer = errors.New("hubnet: peer device is revoked")

// failClosedCandidateChecker rejects every candidate. Until the real UDP
// reachability path (HN-308) lands, a default-less agent never opens a data
// path: it fails closed rather than trusting unverified transport metadata.
type failClosedCandidateChecker struct{}

func (failClosedCandidateChecker) Check(context.Context, protocol.Candidate) error {
	return errors.New("hubnet: candidate reachability checker unavailable")
}

// failClosedHandshakeChecker never confirms a handshake for the same reason.
type failClosedHandshakeChecker struct{}

func (failClosedHandshakeChecker) Wait(context.Context, []byte) error {
	return errors.New("hubnet: handshake checker unavailable")
}

// grantResponse mirrors the Hub network/connection/grant reply. hub-server
// returns the bare ConnectionGrant; we accept either a bare grant or
// {grant: ConnectionGrant} so future envelopes stay backward compatible.
type grantResponse struct {
	Grant protocol.ConnectionGrant `json:"grant"`
}

// decodeGrantResponse normalizes the channel-go response into a
// protocol.ConnectionGrant. hub-server returns the bare grant; the in-process
// test hub wraps it under {"grant": ...}. We accept both shapes and the
// already-typed case (inline transport).
func decodeGrantResponse(raw any) (protocol.ConnectionGrant, error) {
	if raw == nil {
		return protocol.ConnectionGrant{}, errors.New("empty grant response")
	}
	if typed, ok := raw.(protocol.ConnectionGrant); ok {
		return typed, nil
	}
	if typed, ok := raw.(grantResponse); ok {
		return typed.Grant, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return protocol.ConnectionGrant{}, fmt.Errorf("encode response: %w", err)
	}
	// Try wrapped first (test hub), then bare grant (hub-server).
	var wrapped grantResponse
	if err := json.Unmarshal(encoded, &wrapped); err == nil && wrapped.Grant.GrantID != "" {
		return wrapped.Grant, nil
	}
	var bare protocol.ConnectionGrant
	if err := json.Unmarshal(encoded, &bare); err != nil {
		return protocol.ConnectionGrant{}, fmt.Errorf("decode response: %w", err)
	}
	return bare, nil
}
