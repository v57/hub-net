package e2e

// testhub.go is an in-process Hub control-plane double used by the agent-level
// end-to-end tests. It speaks the real hub-pro network/* wire contract over a
// real channel-go server (HTTP/WebSocket on an ephemeral port), reusing the
// shared protocol.* signing primitives. This is NOT a hub-pro replacement:
// cross-language conformance is already locked by the shared fixtures
// validated under HN-076/HN-077. The double exists so a Go test can exercise
// hubnet.Agent.ConnectToShare against a real Hub transport without booting the
// Bun process.
//
// The double implements only what the agent needs from hub-pro for HN-310:
//
//   - hub/net/bind: allocate a stable overlay address pair and echo
//     the trusted Hub signing key + network id so the agent can build a
//     grant.LocalBinding without a separate trust channel.
//   - network/shares/replace: re-verify each AgentAttestation signature under
//     the registering agent's key, record the live provider, return
//     NetworkSharePublication values.
//   - network/connection/grant: build and sign a ConnectionGrant authorizing
//     the caller to reach a published provider.
//   - hub/service/update, hub/profile/update: ack only (the agent pushes these
//     on connect; the double tolerates them).
//
// Authorization policy is intentionally permissive: every authenticated agent
// may reach every published resource. hub-pro's permission model (hub/group/
// keys/private/disabled) is exercised by the hub-pro unit tests; the e2e
// harness cares only about the agent's data-plane wiring.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/v57/channel-go/channelgo"
	"github.com/v57/channel-go/server"
	protocol "github.com/v57/hub-net-node/models"
	hubservice "github.com/v57/hub-service-go"
)

// HubNetworkIDAgent is the overlay network identifier the agent-level test Hub
// advertises. Distinct from the component-level HubNetworkID so the two
// harnesses cannot be confused.
const HubNetworkIDAgent = "hnet-e2e-agent"

// TestHub is an in-process hub-pro double over a real channel-go server.
type TestHub struct {
	mu         sync.Mutex
	hubPublic  ed25519.PublicKey
	hubPrivate ed25519.PrivateKey
	hubKey     string
	srv        *server.Server
	ch         *channelgo.Channel

	nextV4    uint32
	profiles  map[string]*hubProfile  // keyed by key
	providers map[string]*hubProvider // keyed by resourceID
	resGen    map[string]uint64       // keyed by resourceID
	rpcAccess map[string]bool         // keyed by caller key
	netAccess map[string]bool         // keyed by caller key
	registers map[string]int          // successful registrations by key
	replaces  map[string]int          // successful share replacements by service key

	// Device mode (NewDeviceTestHub) mirrors a device-aware hub-pro: it
	// answers hub/info, checks v1 tokens and device certificates, and keys
	// members by device:<id>. members maps service keys to member keys.
	devices  bool
	members  map[string]string
	connects []Connect
	revoked  []map[string]any
}

// Connect records one connection's auth version and device attachment.
type Connect struct {
	Key     string
	Version string
	Device  string
}

type hubProfile struct {
	key               string
	wireGuardKey      string
	overlayV4         string
	overlayV6         string
	ownerServiceKey   string
	attestationSigner ed25519.PublicKey // SPKI-decoded agent key, for share re-verify
}

type hubProvider struct {
	resourceID string
	providerID string
	key        string
	serviceKey string
	protocol   string
	overlay    string
	port       uint16
}

// NewTestHub starts an in-process Hub on an ephemeral port. Stop with Close.
func NewTestHub() (*TestHub, error) {
	return newTestHub(false)
}

// NewDeviceTestHub starts a TestHub in device mode: hub/info, v1 tokens,
// device-attached connections, members keyed by device:<id>, and one network
// endpoint per device (Docs/Devices/protocol.md sections 2, 3 and 10).
func NewDeviceTestHub() (*TestHub, error) {
	return newTestHub(true)
}

func newTestHub(devices bool) (*TestHub, error) {
	hubPublic, hubPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("testhub: generate hub key: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(hubPublic)
	if err != nil {
		return nil, fmt.Errorf("testhub: marshal hub key: %w", err)
	}
	h := &TestHub{
		hubPublic:  hubPublic,
		hubPrivate: hubPrivate,
		hubKey:     base64.StdEncoding.EncodeToString(der),
		ch:         channelgo.NewChannel(),
		profiles:   make(map[string]*hubProfile),
		providers:  make(map[string]*hubProvider),
		resGen:     make(map[string]uint64),
		rpcAccess:  make(map[string]bool),
		netAccess:  make(map[string]bool),
		registers:  make(map[string]int),
		replaces:   make(map[string]int),
		devices:    devices,
		members:    make(map[string]string),
		nextV4:     100<<24 | 96<<16 | 0<<8 | 2, // 100.96.0.2, first allocatable
	}
	h.registerHandlers()
	srv, err := server.Listen(h.ch, 0, h.serverOptions())
	if err != nil {
		return nil, fmt.Errorf("testhub: listen: %w", err)
	}
	h.srv = srv
	return h, nil
}

func (h *TestHub) serverOptions() server.Options {
	return server.Options{
		State: func(headers map[string]string) any {
			// The agent authenticates with header "auth" = key.{pubB64}.{sig}.{exp}.
			// We trust the stated public key as the agent's identity; hub-pro
			// re-verifies the signature, but for the harness the connection's
			// stated key is sufficient because the test owns both ends.
			token := headers["auth"]
			pub, ok := parseAuthKey(token)
			if !ok {
				return map[string]any{}
			}
			if !h.devices {
				return map[string]any{"key": pub}
			}
			state := map[string]any{}
			version := headers["v"]
			if version == "1" && !verifyHubToken(token, h.hubKey) {
				h.recordConnect(Connect{Version: version})
				return state // a refused token: anonymous
			}
			state["key"] = pub
			connect := Connect{Key: pub, Version: version}
			// Certificates attach only hub-bound (v1) connections.
			if version == "1" {
				if device, ok := certifiedDevice(headers["device"], pub); ok {
					state["device"] = device
					connect.Device = device
				}
			}
			h.recordConnect(connect)
			return state
		},
	}
}

func (h *TestHub) recordConnect(connect Connect) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.connects = append(h.connects, connect)
}

// Connects lists every connection's auth version and device (device mode).
func (h *TestHub) Connects() []Connect {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Connect(nil), h.connects...)
}

// MemberKey is the member key a service key is bound under ("" if unbound).
func (h *TestHub) MemberKey(serviceKey string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.members[serviceKey]
}

// verifyHubToken checks a v1 token's signature over hub1:<hubKey>:<expiry>.
func verifyHubToken(token, hubKey string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return false
	}
	public, err := parseSPKI(parts[1])
	if err != nil {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(parts[2])
	return err == nil && ed25519.Verify(public, []byte("hub1:"+hubKey+":"+parts[3]), signature)
}

// certifiedDevice returns the device id of a valid certificate for service.
func certifiedDevice(header, service string) (string, bool) {
	if header == "" {
		return "", false
	}
	certificate, err := hubservice.VerifyCertificate(header)
	now := time.Now().Unix()
	if err != nil || certificate.Service != service || certificate.Exp <= now-30 || certificate.Iat > now+30 {
		return "", false
	}
	der, err := base64.StdEncoding.DecodeString(certificate.Device)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:32], true
}

func parseSPKI(encoded string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ed25519 key")
	}
	return public, nil
}

// Port returns the ephemeral TCP port the Hub listens on.
func (h *TestHub) Port() int {
	addr := h.srv.Addr()
	_, port, ok := strings.Cut(addr, ":")
	if !ok {
		return 0
	}
	n := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// HubKey returns the trusted Hub signing public key, base64 SPKI.
func (h *TestHub) HubKey() string { return h.hubKey }

// Close stops the Hub server.
func (h *TestHub) Close() error { return h.srv.Stop() }

// Restart drops every active transport and starts the same Hub channel on the
// same port. Agent clients must reconnect, replay registration, and keep their
// persistent profile identity and stable overlay allocation.
func (h *TestHub) Restart() error {
	port := h.Port()
	if port == 0 {
		return fmt.Errorf("testhub: cannot resolve restart port")
	}
	if err := h.srv.Stop(); err != nil {
		return fmt.Errorf("testhub: stop for restart: %w", err)
	}
	srv, err := server.Listen(h.ch, port, h.serverOptions())
	if err != nil {
		return fmt.Errorf("testhub: restart listen: %w", err)
	}
	h.srv = srv
	return nil
}

// RegistrationCount reports successful profile registrations for key.
func (h *TestHub) RegistrationCount(key string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.registers[key]
}

// ShareReplaceCount reports successful atomic share replacements for a
// service identity, including reconnect republications.
func (h *TestHub) ShareReplaceCount(serviceKey string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.replaces[serviceKey]
}

// Revoke bumps the resource generation, mirroring hub-pro revokeResource. The
// next grant issuance carries the new generation; agents with older grants
// fail verification against the current generation.
func (h *TestHub) Revoke(resourceID string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.resGen[resourceID]++
	return h.resGen[resourceID]
}

// SetRPCAccess and SetNetworkAccess model Hub's independent authorization
// planes. Missing entries default to allowed so existing agent tests retain
// their permissive setup.
func (h *TestHub) SetRPCAccess(key string, allowed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rpcAccess[key] = allowed
}

func (h *TestHub) SetNetworkAccess(key string, allowed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.netAccess[key] = allowed
}

func (h *TestHub) registerHandlers() {
	h.ch.Post("hub/service/update", func(body channelgo.Body) (any, error) {
		return "ok", nil
	})
	h.ch.Post("hub/info", func(body channelgo.Body) (any, error) {
		if !h.devices {
			return nil, fmt.Errorf("api not found")
		}
		return map[string]any{"key": h.hubKey, "protocol": 1, "pro": true, "mode": "default-allow"}, nil
	})
	h.ch.Post("hub/profile/update", func(body channelgo.Body) (any, error) {
		return "ok", nil
	})
	h.ch.Stream("network/agents/list", func(body channelgo.Body, emit channelgo.StreamEmitter) error {
		if !h.devices {
			return fmt.Errorf("api not found")
		}
		return h.streamSnapshot(emit, h.agentsLocked)
	})
	h.ch.Stream("network/devices/revoked", func(body channelgo.Body, emit channelgo.StreamEmitter) error {
		if !h.devices {
			return fmt.Errorf("api not found")
		}
		return h.streamSnapshot(emit, func() any { return append([]map[string]any{}, h.revoked...) })
	})
	h.ch.Post("hub/net/bind", func(body channelgo.Body) (any, error) {
		return h.handleAgentRegister(body)
	})
	h.ch.Post("network/shares/replace", func(body channelgo.Body) (any, error) {
		return h.handleSharesReplace(body)
	})
	h.ch.Post("network/connection/grant", func(body channelgo.Body) (any, error) {
		return h.handleConnectionGrant(body)
	})
	h.ch.Post("s3/read", func(body channelgo.Body) (any, error) {
		stateMap, _ := body.State.(map[string]any)
		callerKey, _ := stateMap["key"].(string)
		h.mu.Lock()
		allowed, configured := h.rpcAccess[callerKey]
		h.mu.Unlock()
		if configured && !allowed {
			return nil, fmt.Errorf("testhub: RPC permission denied")
		}
		return "https://files.hub.invalid/object?signature=test", nil
	})
}

// streamSnapshot emits value() once and ends the stream. channel-go's server
// sends only from its own loop, so the double can't push later changes on an
// open stream; tests reconnect agents (Restart) to deliver a new snapshot,
// which hub-pro would push on the open stream.
func (h *TestHub) streamSnapshot(emit channelgo.StreamEmitter, value func() any) error {
	h.mu.Lock()
	current := value()
	h.mu.Unlock()
	return emit.Emit(current)
}

func (h *TestHub) agentsLocked() any {
	profiles := make([]map[string]any, 0, len(h.profiles))
	for _, prof := range h.profiles {
		profiles = append(profiles, map[string]any{
			"version": protocol.WireVersion, "key": prof.key, "wireGuardKey": prof.wireGuardKey,
			"overlayAddresses": []string{prof.overlayV4, prof.overlayV6},
			"connectedAt":      time.Now().UTC().Format(time.RFC3339Nano), "online": true,
		})
	}
	return profiles
}

// RevokeDevice removes a device member, as hub/device/revoke does, and lists
// its WireGuard key on network/devices/revoked (sent on the next subscribe).
func (h *TestHub) RevokeDevice(member string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	entry := map[string]any{"device": strings.TrimPrefix(member, "device:"), "wireGuardKeys": []string{},
		"at": time.Now().UTC().Format(time.RFC3339)}
	if prof := h.profiles[member]; prof != nil {
		entry["wireGuardKeys"] = []string{prof.wireGuardKey}
		delete(h.profiles, member)
	}
	h.revoked = append(h.revoked, entry)
}

func (h *TestHub) handleAgentRegister(body channelgo.Body) (any, error) {
	bodyMap, _ := body.Body.(map[string]any)
	if bodyMap == nil {
		return nil, fmt.Errorf("testhub: invalid register body")
	}
	stateMap, _ := body.State.(map[string]any)
	key, _ := stateMap["key"].(string)
	wireGuardKey, _ := bodyMap["wireGuardKey"].(string)
	if key == "" || wireGuardKey == "" {
		return nil, fmt.Errorf("testhub: register requires authenticated key and wireGuardKey")
	}
	member := key
	if device, _ := stateMap["device"].(string); device != "" {
		member = "device:" + device
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	prof := h.profiles[member]
	if prof != nil && prof.ownerServiceKey != key {
		return nil, fmt.Errorf("device_endpoint_exists")
	}
	h.members[key] = member
	if prof == nil {
		v4, v6 := h.allocateOverlayLocked()
		prof = &hubProfile{
			key:             member,
			wireGuardKey:    wireGuardKey,
			overlayV4:       v4,
			overlayV6:       v6,
			ownerServiceKey: key,
		}
		h.profiles[member] = prof
	} else {
		// Reconnect: keep the stable overlay, refresh mutable fields.
		prof.wireGuardKey = wireGuardKey
	}
	h.registers[member]++
	// The attestation signer is the agent's SPKI-decoded Ed25519 key, decoded
	// lazily at share-replace time. Stored as base64 here.
	return map[string]any{
		"success": true,
		"profile": map[string]any{
			"version":          protocol.WireVersion,
			"key":              member,
			"wireGuardKey":     wireGuardKey,
			"overlayAddresses": []string{prof.overlayV4, prof.overlayV6},
			"connectedAt":      time.Now().UTC().Format(time.RFC3339Nano),
		},
		"hubKey":       h.hubKey,
		"hubNetworkId": HubNetworkIDAgent,
	}, nil
}

func (h *TestHub) handleSharesReplace(body channelgo.Body) (any, error) {
	bodyMap, _ := body.Body.(map[string]any)
	if bodyMap == nil {
		return nil, fmt.Errorf("testhub: invalid shares body")
	}
	sharesRaw, _ := bodyMap["shares"].([]any)
	stateMap, _ := body.State.(map[string]any)
	serviceKey, _ := stateMap["key"].(string)
	if serviceKey == "" {
		return nil, fmt.Errorf("testhub: shares replace requires authenticated agent")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// Drop previous providers from this connection (atomic replace semantics).
	h.clearOwnerProvidersLocked(serviceKey)
	publications := make([]map[string]any, 0, len(sharesRaw))
	for _, shareAny := range sharesRaw {
		shareMap, _ := shareAny.(map[string]any)
		if shareMap == nil {
			continue
		}
		att, err := decodeAttestation(shareMap["attestation"])
		if err != nil {
			return nil, fmt.Errorf("testhub: decode attestation: %w", err)
		}
		if att.ServiceKey != serviceKey {
			return nil, fmt.Errorf("testhub: attestation serviceKey %s != connection %s", att.ServiceKey, serviceKey)
		}
		prof := h.profileLocked(att.Key)
		if prof == nil {
			return nil, fmt.Errorf("testhub: attesting agent %s not registered", att.Key)
		}
		if err := verifyAgentAttestation(att, prof); err != nil {
			return nil, fmt.Errorf("testhub: verify attestation: %w", err)
		}
		// A share's address is its service's device: only that device's
		// agent may front it.
		if device, _ := stateMap["device"].(string); h.devices && device != "" &&
			strings.HasPrefix(prof.key, "device:") && prof.key != "device:"+device {
			return nil, fmt.Errorf("share_device_mismatch")
		}
		name, _ := shareMap["name"].(string)
		proto, _ := shareMap["protocol"].(string)
		target, _ := shareMap["target"].(map[string]any)
		port := uint16(0)
		if target != nil {
			if portF, ok := target["port"].(float64); ok {
				port = uint16(portF)
			}
		}
		resourceID := resourceIDFor(serviceKey, name)
		providerID := providerIDFor(prof.key, resourceID)
		h.providers[resourceID] = &hubProvider{
			resourceID: resourceID,
			providerID: providerID,
			key:        prof.key,
			serviceKey: serviceKey,
			protocol:   proto,
			overlay:    prof.overlayV4,
			port:       port,
		}
		if _, ok := h.resGen[resourceID]; !ok {
			h.resGen[resourceID] = 1
		}
		publications = append(publications, map[string]any{
			"version":        protocol.WireVersion,
			"resourceId":     resourceID,
			"authority":      name + ".hub.invalid",
			"providerId":     providerID,
			"protocol":       proto,
			"overlayAddress": prof.overlayV4,
			"port":           port,
		})
	}
	h.replaces[serviceKey]++
	return map[string]any{"shares": publications}, nil
}

func (h *TestHub) handleConnectionGrant(body channelgo.Body) (any, error) {
	bodyMap, _ := body.Body.(map[string]any)
	if bodyMap == nil {
		return nil, fmt.Errorf("testhub: invalid grant body")
	}
	callerWireGuardKey, _ := bodyMap["callerWireGuardKey"].(string)
	resourceID, _ := bodyMap["resourceId"].(string)
	if callerWireGuardKey == "" || resourceID == "" {
		return nil, fmt.Errorf("testhub: grant requires callerWireGuardKey and resourceId")
	}
	stateMap, _ := body.State.(map[string]any)
	callerKey, _ := stateMap["key"].(string)
	h.mu.Lock()
	defer h.mu.Unlock()
	if allowed, configured := h.netAccess[callerKey]; configured && !allowed {
		return nil, fmt.Errorf("testhub: network permission denied")
	}
	caller := h.profileLocked(callerKey)
	if caller == nil || caller.ownerServiceKey != callerKey || caller.wireGuardKey != callerWireGuardKey {
		return nil, fmt.Errorf("testhub: caller profile not registered or mismatched")
	}
	provider := h.providers[resourceID]
	if provider == nil {
		return nil, fmt.Errorf("testhub: no provider for resource %s", resourceID)
	}
	target := h.profileLocked(provider.key)
	if target == nil {
		return nil, fmt.Errorf("testhub: provider agent %s not connected", provider.key)
	}
	destinationIsV6 := strings.Contains(provider.overlay, ":")
	callerAddress := caller.overlayV4
	if destinationIsV6 {
		callerAddress = caller.overlayV6
	}
	now := time.Now().UTC()
	grant := protocol.ConnectionGrant{
		Version:            protocol.WireVersion,
		GrantID:            "grant-" + resourceID + "-" + callerKey,
		HubKey:             h.hubKey,
		HubNetworkID:       HubNetworkIDAgent,
		CallerKey:          caller.key,
		CallerWireGuardKey: callerWireGuardKey,
		CallerAddress:      callerAddress,
		TargetKey:          target.key,
		TargetWireGuardKey: target.wireGuardKey,
		ResourceID:         resourceID,
		ProviderID:         provider.providerID,
		Protocol:           provider.protocol,
		DestinationAddress: provider.overlay,
		DestinationPort:    provider.port,
		Generation:         h.resGen[resourceID],
		IssuedAt:           now.Format(time.RFC3339Nano),
		ExpiresAt:          now.Add(protocol.ConnectionGrantMaxLifetime - time.Second).Format(time.RFC3339Nano),
	}
	signature, err := protocol.SignEnvelope(protocol.PurposeConnectionGrant, grant, h.hubPrivate)
	if err != nil {
		return nil, fmt.Errorf("testhub: sign grant: %w", err)
	}
	grant.Signature = signature
	return map[string]any{"grant": grant}, nil
}

func (h *TestHub) allocateOverlayLocked() (string, string) {
	// Walk 100.96.0.2 .. 100.96.0.254 then 100.96.1.0 ... skipping nothing in
	// the harness (single process, deterministic allocation).
	n := h.nextV4
	h.nextV4++
	v4 := fmt.Sprintf("%d.%d.%d.%d", byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	// IPv6 is derived deterministically from the same counter inside the
	// overlay prefix so each agent gets a unique pair.
	v6 := fmt.Sprintf("fd48:5542:4e45::%x:%x", byte(n>>8), byte(n))
	if _, err := netip.ParseAddr(v4); err != nil {
		panic(fmt.Sprintf("testhub: bad v4 %s: %v", v4, err))
	}
	if _, err := netip.ParseAddr(v6); err != nil {
		panic(fmt.Sprintf("testhub: bad v6 %s: %v", v6, err))
	}
	return v4, v6
}

// profileLocked finds a member by member key or by its service key.
func (h *TestHub) profileLocked(key string) *hubProfile {
	if prof := h.profiles[key]; prof != nil {
		return prof
	}
	return h.profiles[h.members[key]]
}

func (h *TestHub) clearOwnerProvidersLocked(ownerKey string) {
	for rid, prov := range h.providers {
		if prov.serviceKey == ownerKey {
			delete(h.providers, rid)
		}
	}
}

// parseAuthKey extracts the base64 SPKI public key from a Hub auth token of
// the form "key.{pub}.{sig}.{expiry}". Returns false if the shape is wrong.
func parseAuthKey(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 || parts[0] != "key" {
		return "", false
	}
	return parts[1], true
}

// decodeAttestation reconstructs a protocol.AgentAttestation from a decoded
// JSON map. Channel decodes JSON bodies into map[string]any, so we round-trip
// through re-encoding for type safety.
func decodeAttestation(raw any) (protocol.AgentAttestation, error) {
	if raw == nil {
		return protocol.AgentAttestation{}, fmt.Errorf("missing attestation")
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return protocol.AgentAttestation{}, err
	}
	var att protocol.AgentAttestation
	if err := json.Unmarshal(encoded, &att); err != nil {
		return protocol.AgentAttestation{}, err
	}
	return att, nil
}

// verifyAgentAttestation re-checks the attestation signature against the
// registering agent's public key, mirroring hub-pro verifyAttestation. The
// agent key arrives base64 SPKI; we decode and verify under the
// agent-attestation domain.
func verifyAgentAttestation(att protocol.AgentAttestation, prof *hubProfile) error {
	if att.Version != protocol.WireVersion || att.AttestationID == "" {
		return fmt.Errorf("invalid attestation envelope")
	}
	der, err := base64.StdEncoding.DecodeString(prof.ownerServiceKey)
	if err != nil {
		return fmt.Errorf("decode agent key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("parse agent key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("agent key is not Ed25519")
	}
	ok, err = protocol.VerifyEnvelope(protocol.PurposeAgentAttestation, att, pub, att.Signature)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if !ok {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func resourceIDFor(key, shareName string) string {
	// Mirror hub-pro's stable resourceId derivation (owner key + share name).
	// The exact hash is hub-pro's concern; the harness needs only stability.
	return "hnr-" + shortHash(key) + "-" + shareName
}

func providerIDFor(key, resourceID string) string {
	return "prov-" + shortHash(key) + "-" + resourceID
}

func shortHash(value string) string {
	// Deterministic short identifier; collisions within a single test run are
	// not a concern because key/key are unique per agent.
	if len(value) > 8 {
		return value[len(value)-8:]
	}
	return value
}
