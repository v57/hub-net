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
	"net/netip"
	"sync"

	"github.com/v57/channel-go/channelgo"
	"github.com/v57/hub-net/config"
	"github.com/v57/hub-net/connection"
	"github.com/v57/hub-net/control"
	"github.com/v57/hub-net/dnsresolver"
	"github.com/v57/hub-net/enforcement"
	"github.com/v57/hub-net/grant"
	"github.com/v57/hub-net/ipc"
	"github.com/v57/hub-net/keychain"
	"github.com/v57/hub-net/logging"
	"github.com/v57/hub-net/platform"
	"github.com/v57/hub-net/profile"
	"github.com/v57/hub-net/version"
	"github.com/v57/hub-net/wireguard"
	hubservice "github.com/v57/hub-service-go"
	"github.com/v57/hub-service-go/identity"
	"github.com/v57/hub-service-go/protocol"
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
	hubService *hubservice.Service
	control    *control.Controller
	profileID  *identity.Identity
	wgPrivate  []byte
	started    bool
	prepared   bool
	cancelRun  context.CancelFunc
	networkUp  bool

	// Grant/connection/enforcement wiring (HN-308/310). The verifier is built
	// lazily from the first signature-verified grant, since hub-pro does not
	// expose its signing key over the register path today. The connection
	// manager is constructed in Prepare from injected or default adapters.
	connections        *connection.Manager
	grantVerifier      *grant.Verifier
	enforcementMgr     *enforcement.Manager
	enforcementBackend enforcement.Backend
	production         bool
	interfaceName      string
	candidateChecker   connection.CandidateChecker
	handshakeChecker   connection.HandshakeChecker
	preflight          func() error

	// Trusted per-resource authorization generations. The production agent
	// populates this from a network/resource/generations subscription; the
	// test harness injects values directly.
	genMu       sync.RWMutex
	generations map[string]uint64
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
	// Preflight overrides the production probe in tests.
	Preflight func() error
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
		enforcementBackend: enforcementBackend,
		production:         options.Production,
		interfaceName:      interfaceName,
		generations:        make(map[string]uint64),
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

	prof, err := profile.New(profileID)
	if err != nil {
		return fmt.Errorf("hubnet: build profile: %w", err)
	}
	pub, err := wireGuardPublicKey(wgPrivate)
	if err != nil {
		return fmt.Errorf("hubnet: derive wireguard public key: %w", err)
	}
	prof.SetWireGuardPublicKey(pub)
	a.profile = prof

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

	agentKey, err := profileID.PublicKeyBase64()
	if err != nil {
		return fmt.Errorf("hubnet: read profile public key: %w", err)
	}
	registrar, err := profile.NewRegistrar(profile.RegistrarOptions{
		Profile:  prof,
		AgentKey: agentKey,
		Name:     "hub-net",
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
func (a *Agent) Run(ctx context.Context) error {
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

	svc, err := hubservice.New(hubservice.Options{
		Identity: a.profileID,
		Address:  a.config.HubAddress,
		Name:     "hub-net",
		OnConnect: func(sender *channelgo.Sender) {
			if a.registrar == nil {
				return
			}
			if err := a.registrar.Register(runCtx, sender); err != nil {
				a.resolver.Deactivate()
				a.logger.Error("profile register failed", slog.String("err", err.Error()))
				return
			}
			if err := a.configureInterface(); err != nil {
				a.resolver.Deactivate()
				a.profile.SetState(profile.StateUnregistered)
				a.logger.Error("wireguard interface setup failed", slog.String("err", err.Error()))
				return
			}
			if a.production {
				if err := a.dnsServer.Install(runCtx); err != nil {
					_ = a.stopInterface()
					a.resolver.Deactivate()
					a.profile.SetState(profile.StateUnregistered)
					a.logger.Error("split DNS setup failed", slog.String("err", err.Error()))
					return
				}
			}
			a.resolver.Activate()
		},
	})
	if err != nil {
		return fmt.Errorf("hubnet: build hub service: %w", err)
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
	a.control = controller
	a.hubService = svc
	defer svc.Stop()
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
	if err := svc.Start(); err != nil {
		return fmt.Errorf("hubnet: start hub service: %w", err)
	}

	// HN-302: bring up the local IPC server so services on this machine can
	// request share attestations. The server fails closed: if it cannot bind
	// the socket, the agent returns an error rather than advertising a
	// profile without a working publication path.
	ipcCtx, ipcCancel := context.WithCancel(runCtx)
	a.mu.Lock()
	a.ipcCancel = ipcCancel
	a.mu.Unlock()
	ipcErrs := a.ipcServer.Start(ipcCtx)
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

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.networkUp {
		if err := a.adapter.Down(); err != nil {
			return fmt.Errorf("hubnet: replace wireguard interface: %w", err)
		}
		a.networkUp = false
	}
	config := wireguard.InterfaceConfig{
		Name:       a.interfaceName,
		PrivateKey: append([]byte(nil), a.wgPrivate...),
		Address:    address,
		ListenPort: wireguard.DefaultPort,
	}
	if err := a.adapter.Up(config); err != nil {
		_ = a.adapter.Down()
		return fmt.Errorf("hubnet: start wireguard interface: %w", err)
	}
	a.networkUp = true
	return nil
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
func (a *Agent) HubService() *hubservice.Service { return a.hubService }

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
		CallerProfileKey:   snap.ProfileKey,
		CallerWireGuardKey: localWireGuardKey,
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
		"callerProfileKey":   snap.ProfileKey,
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
	return a.enforcementMgr.Authorize(grantValue)
}

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

// grantResponse mirrors the Hub network/connection/grant reply. hub-pro
// returns the bare ConnectionGrant; we accept either a bare grant or
// {grant: ConnectionGrant} so future envelopes stay backward compatible.
type grantResponse struct {
	Grant protocol.ConnectionGrant `json:"grant"`
}

// decodeGrantResponse normalizes the channel-go response into a
// protocol.ConnectionGrant. hub-pro returns the bare grant; the in-process
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
	// Try wrapped first (test hub), then bare grant (hub-pro).
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
