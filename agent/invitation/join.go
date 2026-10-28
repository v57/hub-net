// Joiner direct bootstrap client.
//
// Join performs the complete invitation join on behalf of a Go joiner: it
// authenticates with hub-net-node (UDP probe + session.open with the compact
// invitation), learns the inviter's bootstrap endpoint from the paired
// session, exchanges a signed DirectBootstrapRequest over UDP framing,
// installs the temporary point-to-point WireGuard link, and binds the joiner
// identity at hub-server through the inviter (hub/net/bind with bindingKind
// "join"). The joiner's service key both signs the bootstrap request and
// authenticates the hub-server bind, so the inviter and hub-server see the same
// identity.
package invitation

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/v57/channel-go/channelgo"
	"github.com/v57/hub-net-node/identity"
	protocol "github.com/v57/hub-net-node/models"
	nodeprotocol "github.com/v57/hub-net-node/protocol"
	"github.com/v57/hub-net/hubconn"
	"github.com/v57/hub-net/nodeclient"
	"github.com/v57/hub-net/wireguard"
	hubservice "github.com/v57/hub-service-go"
)

// joinTimeout bounds the rendezvous phase (probe, session pairing, candidate
// delivery). The direct exchange has its own bounded retries.
const joinTimeout = 30 * time.Second

// JoinOptions configures one invitation join.
type JoinOptions struct {
	// Code is the compact invitation code or hub://join/ URL.
	Code string
	// Identity is the joiner's fresh service identity. It signs the direct
	// bootstrap request and authenticates the hub/net/bind.
	Identity *identity.Identity
	// WireGuardKey is the joiner's 32-byte Curve25519 private key.
	WireGuardKey []byte
	// InterfaceName is the temporary WireGuard interface name. Empty defaults
	// to hubnet0.
	InterfaceName string
	// ListenPort is the WireGuard listen port. Defaults to
	// wireguard.DefaultPort.
	ListenPort uint16
	// Adapter installs and removes the temporary point-to-point link.
	Adapter wireguard.Adapter
	// Binder authenticates with hub-server and issues hub/net/bind. Defaults to
	// the real hubservice binder.
	Binder Binder
	// Device certifies Identity with this device's key at hub/net/bind, as
	// the daemon session does on every connect. The Hub keys a device's
	// addresses by the device, so the join and the session then land on the
	// same ones. Nil binds the key alone.
	Device *hubservice.DeviceKey
	// Logger receives progress. Defaults to a discard logger.
	Logger *slog.Logger
	// Timeout bounds the whole join (rendezvous, direct exchange, and bind).
	// Defaults to joinTimeout.
	Timeout time.Duration
	// Now is the clock; tests inject a controllable time.
	Now func() time.Time
}

// JoinResult is the outcome of a completed join: the inviter's temporary
// bootstrap link plus the permanent membership issued by hub-server.
type JoinResult struct {
	// ReplayID is the SHA-256 payload digest (unpadded base64url) of the
	// compact invitation. It is the transaction id used across the node
	// session, the direct bootstrap request, and staging.
	ReplayID string
	// InvitingKey is the inviter service public key (SPKI base64) that signed
	// the invitation and the direct bootstrap response.
	InvitingKey string
	// InviterServiceKey and InviterWireGuardKey identify the inviter's
	// temporary peer.
	InviterServiceKey   string
	InviterWireGuardKey []byte
	// Endpoint is the inviter's WireGuard UDP endpoint (host:port).
	Endpoint string
	// JoinerAddress and InviterAddress are the temporary point-to-point
	// addresses installed on the bootstrap link.
	JoinerAddress  protocol.BootstrapAddress
	InviterAddress protocol.BootstrapAddress
	// HubProHost is the inviter's overlay address where hub-server listens on
	// :1997; the joiner reaches it through the temporary link.
	HubProHost string
	// Node is the hub-net-node endpoint from the invitation (scheme included).
	Node string
	// Permanent membership returned by hub/net/bind.
	HubKey           string
	HubNetworkID     string
	OverlayAddresses []string
	// HubName is the hub/header display name at bind time.
	HubName string
}

// Binder authenticates the joiner at hub-server through the temporary link and
// issues hub/net/bind with bindingKind "join".
type Binder interface {
	// Bind issues the joiner's first hub/net/bind. admission is the
	// inviter-signed bootstrap response hub-server requires to admit a new key.
	Bind(ctx context.Context, address any, id *identity.Identity, wireGuardKey, name string, admission protocol.DirectBootstrapResponse) (BindResult, error)
}

// BindResult is the permanent membership issued by hub-server.
type BindResult struct {
	HubKey           string
	HubNetworkID     string
	OverlayAddresses []string
	HeaderName       string
}

// Join performs the full invitation join. The temporary link is left up on
// success so the calling daemon session can adopt it (its interface Up must
// re-install the inviter peer — see InitialPeers); on any failure the link is
// torn down.
func Join(ctx context.Context, options JoinOptions) (JoinResult, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if options.Identity == nil {
		return JoinResult{}, errors.New("invitation: joiner identity required")
	}
	if len(options.WireGuardKey) != 32 {
		return JoinResult{}, errors.New("invitation: joiner wireguard key must be 32 bytes")
	}
	if options.Adapter == nil {
		return JoinResult{}, errors.New("invitation: joiner adapter required")
	}
	binder := options.Binder
	if binder == nil {
		binder = hubServiceBinder{device: options.Device}
	}

	decoded, err := Decode(options.Code, now())
	if err != nil {
		return JoinResult{}, fmt.Errorf("invitation: join: %w", err)
	}
	replayID := decoded.Envelope.TokenID
	invitingKey := decoded.Envelope.InvitingKey
	serviceKey, err := options.Identity.PublicKeyBase64()
	if err != nil {
		return JoinResult{}, fmt.Errorf("invitation: joiner service key: %w", err)
	}
	wireGuardKey, err := wireGuardPublicKey(options.WireGuardKey)
	if err != nil {
		return JoinResult{}, fmt.Errorf("invitation: joiner wireguard key: %w", err)
	}
	wireGuardKeyB64 := base64.StdEncoding.EncodeToString(wireGuardKey)

	timeout := options.Timeout
	if timeout <= 0 {
		timeout = joinTimeout
	}
	joinCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 1. Node rendezvous: probe + session.open + candidate pairing.
	rendezvousURL, udpEndpoint, err := nodeEndpoints(decoded.Node)
	if err != nil {
		return JoinResult{}, fmt.Errorf("invitation: join: %w", err)
	}
	probe := nodeprotocol.InvitationUDPProbe{
		Version:        protocol.WireVersion,
		InvitationCode: options.Code,
		Key:            wireGuardKeyB64,
		TokenDigest:    replayID,
		TransactionID:  replayID,
	}
	if err := sendInvitationProbe(joinCtx, udpEndpoint, probe); err != nil {
		return JoinResult{}, fmt.Errorf("invitation: join: %w", err)
	}
	peer, err := rendezvous(joinCtx, rendezvousURL, options.Code, wireGuardKeyB64, replayID, invitingKey, options.ListenPort, now())
	if err != nil {
		return JoinResult{}, fmt.Errorf("invitation: join: %w", err)
	}

	// 2. Direct bootstrap exchange with the inviter's listener.
	exchangeAddress, err := bootstrapExchangeAddress(peer.Candidates, peer.Observed)
	if err != nil {
		return JoinResult{}, err
	}
	request, err := buildJoinRequest(replayID, serviceKey, wireGuardKeyB64, options.Identity.PrivateKey(), now())
	if err != nil {
		return JoinResult{}, err
	}
	logger.Info("invitation join: direct bootstrap exchange",
		slog.String("endpoint", exchangeAddress.String()))
	response, err := Exchange(joinCtx, exchangeAddress, request, ExchangeOptions{Now: now})
	if err != nil {
		return JoinResult{}, fmt.Errorf("invitation: join: %w", err)
	}
	// The response must be signed by the key that signed the invitation; a
	// self-asserted inviter key would let an on-path responder forge the
	// bootstrap link.
	if response.InviterServiceKey != invitingKey {
		return JoinResult{}, errors.New("invitation: join: response inviter key does not match invitation")
	}

	// 3. Install the temporary point-to-point WireGuard link.
	endpoint, err := wgEndpoint(response, peer.Observed)
	if err != nil {
		return JoinResult{}, err
	}
	joinerV4, err := netip.ParseAddr(response.JoinerAddress.IPv4)
	if err != nil {
		return JoinResult{}, fmt.Errorf("invitation: join: joiner address: %w", err)
	}
	inviterV4, err := netip.ParseAddr(response.InviterAddress.IPv4)
	if err != nil {
		return JoinResult{}, fmt.Errorf("invitation: join: inviter address: %w", err)
	}
	inviterV6, err := netip.ParseAddr(response.InviterAddress.IPv6)
	if err != nil {
		return JoinResult{}, fmt.Errorf("invitation: join: inviter address: %w", err)
	}
	hubProHost, err := netip.ParseAddr(response.HubProHost)
	if err != nil || !hubProHost.Is4() {
		return JoinResult{}, fmt.Errorf("invitation: join: invalid hubProHost %q", response.HubProHost)
	}
	inviterWireGuard, err := base64.StdEncoding.DecodeString(response.InviterWireGuardKey)
	if err != nil || len(inviterWireGuard) != 32 {
		return JoinResult{}, errors.New("invitation: join: invalid inviter wireguard key")
	}
	interfaceName := options.InterfaceName
	if interfaceName == "" {
		interfaceName = "hubnet0"
	}
	listenPort := options.ListenPort
	if listenPort == 0 {
		listenPort = wireguard.DefaultPort
	}
	if err := options.Adapter.Up(wireguard.InterfaceConfig{
		Name:       interfaceName,
		PrivateKey: append([]byte(nil), options.WireGuardKey...),
		Address:    joinerV4,
		ListenPort: listenPort,
		Peers: []wireguard.PeerConfig{{
			PublicKey: inviterWireGuard,
			AllowedIPs: []netip.Prefix{
				netip.PrefixFrom(inviterV4, 32),
				netip.PrefixFrom(inviterV6, 128),
				netip.PrefixFrom(hubProHost, 32),
			},
			Endpoint: endpoint,
		}},
	}); err != nil {
		return JoinResult{}, fmt.Errorf("invitation: join: install temporary link: %w", err)
	}
	linkUp := true
	defer func() {
		if linkUp {
			_ = options.Adapter.Down()
		}
	}()

	// 4. Bind at hub-server through the inviter.
	hubAddress := bootstrapHubAddress(response.HubProHost)
	logger.Info("invitation join: hub/net/bind", slog.String("hub", hubAddress))
	binding, err := binder.Bind(joinCtx, hubAddress, options.Identity, wireGuardKeyB64, "hub-net", response)
	if err != nil {
		return JoinResult{}, fmt.Errorf("invitation: join: hub/net/bind: %w", err)
	}
	linkUp = false // the daemon session adopts the link from here

	return JoinResult{
		ReplayID:            replayID,
		InvitingKey:         invitingKey,
		InviterServiceKey:   response.InviterServiceKey,
		InviterWireGuardKey: inviterWireGuard,
		Endpoint:            endpoint,
		JoinerAddress:       response.JoinerAddress,
		InviterAddress:      response.InviterAddress,
		HubProHost:          response.HubProHost,
		Node:                decoded.Node,
		HubKey:              binding.HubKey,
		HubNetworkID:        binding.HubNetworkID,
		OverlayAddresses:    binding.OverlayAddresses,
		HubName:             binding.HeaderName,
	}, nil
}

// nodeEndpoints derives the rendezvous WebSocket URL and the UDP probe
// endpoint from the invitation's node value. The invitation node is an
// https(s) URL (the decoder prepends a scheme); the node speaks WebSocket on
// the same host:port with /rendezvous appended, and UDP observation on the
// same port.
func nodeEndpoints(node string) (wsURL string, udp *net.UDPAddr, err error) {
	value := strings.TrimSpace(node)
	if value == "" {
		return "", nil, errors.New("invitation: empty node endpoint")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return "", nil, fmt.Errorf("invitation: invalid node endpoint %q", node)
	}
	scheme := parsed.Scheme
	switch scheme {
	case "https":
		scheme = "wss"
	case "http":
		scheme = "ws"
	case "ws", "wss":
	default:
		return "", nil, fmt.Errorf("invitation: unsupported node scheme %q", parsed.Scheme)
	}
	path := strings.TrimSuffix(parsed.Path, "/") + "/rendezvous"
	wsURL = scheme + "://" + parsed.Host + path
	port := parsed.Port()
	if port == "" {
		if scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	host := parsed.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	udp, err = net.ResolveUDPAddr("udp", host+":"+port)
	if err != nil {
		return "", nil, fmt.Errorf("invitation: resolve node %s: %w", host+":"+port, err)
	}
	return wsURL, udp, nil
}

// sendInvitationProbe records the joiner's source endpoint at the node and
// waits for the acknowledged ticket id. The probe must precede session.open.
func sendInvitationProbe(ctx context.Context, address *net.UDPAddr, probe nodeprotocol.InvitationUDPProbe) error {
	payload, err := json.Marshal(probe)
	if err != nil {
		return fmt.Errorf("invitation: encode probe: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, address)
	if err != nil {
		return fmt.Errorf("invitation: dial node %s: %w", address, err)
	}
	defer conn.Close()
	expected := probe.TokenDigest + ":" + probe.Key
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			if attempt == 2 {
				return fmt.Errorf("invitation: send probe: %w", err)
			}
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		reply := make([]byte, 1024)
		n, err := conn.Read(reply)
		if err != nil {
			if attempt == 2 {
				return fmt.Errorf("invitation: probe response: %w", err)
			}
			continue
		}
		var ack nodeprotocol.UDPProbeResponse
		if json.Unmarshal(reply[:n], &ack) == nil && ack.Version == protocol.WireVersion && ack.TicketID == expected {
			return nil
		}
	}
	return errors.New("invitation: node did not acknowledge probe")
}

// rendezvousPeer is the inviter's side of the paired bootstrap session as
// delivered by candidate.list.
type rendezvousPeer struct {
	Candidates []protocol.Candidate
	Observed   nodeprotocol.ObservedEndpoint
}

// rendezvous opens the invitation session, offers the joiner's candidate, and
// waits for the inviter's candidates and node-observed endpoint. expectedKey
// is the invitation service key (SPKI base64); the inviter's observed
// endpoint and candidates must belong to it.
func rendezvous(ctx context.Context, wsURL, code, key, replayID, expectedKey string, listenPort uint16, now time.Time) (rendezvousPeer, error) {
	conn, err := nodeclient.DialWebSocket(ctx, wsURL)
	if err != nil {
		return rendezvousPeer{}, fmt.Errorf("invitation: rendezvous dial %s: %w", wsURL, err)
	}
	defer conn.Close()

	openRequestID := replayID
	if err := nodeclient.WriteEnvelope(conn, nodeprotocol.Envelope{
		MajorVersion:   nodeprotocol.MajorVersion,
		MinorVersion:   nodeprotocol.MinorVersion,
		Type:           nodeprotocol.MessageOpenSession,
		RequestID:      openRequestID,
		InvitationCode: code,
		Key:            key,
		TokenDigest:    replayID,
		TransactionID:  replayID,
	}); err != nil {
		return rendezvousPeer{}, fmt.Errorf("invitation: session.open: %w", err)
	}

	var sessionID string
	for {
		if err := conn.SetReadDeadline(now.Add(joinTimeout)); err != nil {
			return rendezvousPeer{}, err
		}
		reply, err := nodeclient.ReadEnvelope(conn)
		if err != nil {
			return rendezvousPeer{}, fmt.Errorf("invitation: session.open: %w", err)
		}
		if reply.Type == nodeprotocol.MessageError {
			return rendezvousPeer{}, nodeError(reply)
		}
		if reply.Type != nodeprotocol.MessageSessionOpened || reply.RequestID != openRequestID || reply.SessionID == "" {
			continue
		}
		sessionID = reply.SessionID
		break
	}

	candidateID, err := randomID()
	if err != nil {
		return rendezvousPeer{}, err
	}
	candidate := protocol.Candidate{
		Version:     protocol.WireVersion,
		CandidateID: candidateID,
		SessionID:   sessionID,
		Key:         key,
		Kind:        "host",
		Transport:   "udp",
		Address:     "0.0.0.0",
		Port:        listenPort,
		Priority:    0,
		ExpiresAt:   now.Add(nodeprotocol.DefaultCandidateLifetime).UTC().Format(time.RFC3339Nano),
	}
	if err := nodeclient.WriteEnvelope(conn, nodeprotocol.Envelope{
		MajorVersion: nodeprotocol.MajorVersion,
		MinorVersion: nodeprotocol.MinorVersion,
		Type:         nodeprotocol.MessageOfferCandidate,
		SessionID:    sessionID,
		Candidate:    &candidate,
	}); err != nil {
		return rendezvousPeer{}, fmt.Errorf("invitation: candidate.offer: %w", err)
	}

	// The node pushes a list with only the inviter's observed endpoint as soon
	// as the sessions pair; the inviter's declared candidates (its advertised
	// address, e.g. behind port forwarding) follow with its offer. Wait a
	// moment for them before settling for the observed endpoint.
	var observedOnly *rendezvousPeer
	deadline := now.Add(joinTimeout)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return rendezvousPeer{}, err
		}
		reply, err := nodeclient.ReadEnvelope(conn)
		if err != nil {
			var netErr net.Error
			if observedOnly != nil && errors.As(err, &netErr) && netErr.Timeout() {
				return *observedOnly, nil
			}
			return rendezvousPeer{}, fmt.Errorf("invitation: candidate.list: %w", err)
		}
		if reply.Type == nodeprotocol.MessageError {
			return rendezvousPeer{}, nodeError(reply)
		}
		if reply.Type != nodeprotocol.MessageCandidates || reply.SessionID != sessionID || reply.Observed == nil {
			continue
		}
		observed := *reply.Observed
		if observed.Transport != "udp" || observed.Port == 0 || observed.Key == key ||
			(expectedKey != "" && observed.Key != expectedKey) {
			return rendezvousPeer{}, errors.New("invitation: invalid inviter observed endpoint")
		}
		usable := make([]protocol.Candidate, 0, len(reply.Candidates))
		for _, c := range reply.Candidates {
			if c.SessionID == sessionID && c.Key == observed.Key && c.Transport == "udp" && c.Port != 0 {
				usable = append(usable, c)
			}
		}
		peer := rendezvousPeer{Candidates: usable, Observed: observed}
		if len(usable) > 0 {
			return peer, nil
		}
		if observedOnly == nil {
			observedOnly = &peer
			deadline = time.Now().Add(candidateWait)
		}
	}
}

// candidateWait bounds how long a joiner waits for the inviter's declared
// candidates after the node paired the sessions.
const candidateWait = 3 * time.Second

// buildJoinRequest constructs and signs the joiner's direct bootstrap request.
func buildJoinRequest(replayID, serviceKey, wireGuardKey string, privateKey ed25519.PrivateKey, now time.Time) (protocol.DirectBootstrapRequest, error) {
	nonce, err := randomID()
	if err != nil {
		return protocol.DirectBootstrapRequest{}, err
	}
	request := protocol.DirectBootstrapRequest{
		ReplayID:           replayID,
		JoinerServiceKey:   serviceKey,
		JoinerWireGuardKey: wireGuardKey,
		Nonce:              nonce,
		IssuedAt:           now.UTC().Format(time.RFC3339Nano),
	}
	if err := SignJoinerRequest(&request, privateKey); err != nil {
		return protocol.DirectBootstrapRequest{}, err
	}
	return request, nil
}

// bootstrapExchangeAddress picks the inviter listener endpoint for the direct
// exchange: the first usable declared candidate, else the node-observed
// endpoint.
func bootstrapExchangeAddress(candidates []protocol.Candidate, observed nodeprotocol.ObservedEndpoint) (*net.UDPAddr, error) {
	for _, candidate := range candidates {
		address, err := netip.ParseAddr(candidate.Address)
		if err != nil || address.IsUnspecified() || address.IsMulticast() {
			continue
		}
		return net.ResolveUDPAddr("udp", net.JoinHostPort(candidate.Address, strconv.Itoa(int(candidate.Port))))
	}
	if observed.Transport == "udp" && observed.Port != 0 {
		address, err := netip.ParseAddr(observed.Address)
		if err == nil && !address.IsUnspecified() && !address.IsMulticast() {
			return net.ResolveUDPAddr("udp", net.JoinHostPort(observed.Address, strconv.Itoa(int(observed.Port))))
		}
	}
	return nil, errors.New("invitation: no reachable inviter bootstrap endpoint")
}

// wgEndpoint derives the inviter's WireGuard UDP endpoint for the temporary
// peer: the signed response carries the inviter's WireGuard port on its
// listener address; when that address is unspecified (listener bound to all
// interfaces) the node-observed address is substituted.
func wgEndpoint(response protocol.DirectBootstrapResponse, observed nodeprotocol.ObservedEndpoint) (string, error) {
	if len(response.Endpoints) == 0 {
		return "", errors.New("invitation: inviter response carries no endpoint")
	}
	endpoint := response.Endpoints[0]
	if endpoint.Transport != "udp" || endpoint.Port == 0 {
		return "", errors.New("invitation: inviter endpoint transport or port invalid")
	}
	address := endpoint.Address
	if parsed, err := netip.ParseAddr(address); err != nil || parsed.IsUnspecified() || parsed.IsMulticast() {
		if observed.Transport != "udp" || observed.Port == 0 {
			return "", errors.New("invitation: inviter endpoint address unusable")
		}
		address = observed.Address
	}
	return net.JoinHostPort(address, strconv.Itoa(int(endpoint.Port))), nil
}

// bootstrapHubAddress is the hub-server address the joiner binds through the
// temporary link: the inviter's overlay address on port 1997. The Go
// channel-go client only speaks plain WebSocket, so the scheme is ws://.
func bootstrapHubAddress(hubProHost string) string {
	return "ws://" + net.JoinHostPort(hubProHost, strconv.Itoa(1997))
}

func nodeError(reply nodeprotocol.Envelope) error {
	if reply.Error == nil {
		return errors.New("invitation: node error without details")
	}
	return fmt.Errorf("invitation: node rejected: %s %s", reply.Error.Code, reply.Error.Message)
}

func wireGuardPublicKey(privateKey []byte) ([]byte, error) {
	curve := ecdh.X25519()
	key, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

func randomID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("invitation: random: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// InviterPeer is the persisted inviter peer a joined membership keeps so the
// daemon session can reach hub-server through the temporary bootstrap link after
// the join-time interface configuration is replaced.
type InviterPeer struct {
	Version    int      `json:"version"`
	PublicKey  string   `json:"publicKey"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowedIPs"`
}

// inviterPeerVersion is the InviterPeer file version.
const inviterPeerVersion = 1

// InviterPeerFileName is the per-membership file holding the inviter peer.
const InviterPeerFileName = "inviter.json"

// NewInviterPeer builds the persisted inviter peer from a completed join.
func NewInviterPeer(result JoinResult) InviterPeer {
	return InviterPeer{
		Version:   inviterPeerVersion,
		PublicKey: base64.StdEncoding.EncodeToString(result.InviterWireGuardKey),
		Endpoint:  result.Endpoint,
		AllowedIPs: []string{
			result.InviterAddress.IPv4 + "/32",
			result.InviterAddress.IPv6 + "/128",
			result.HubProHost + "/32",
		},
	}
}

// PeerConfig decodes the peer into adapter configuration.
func (p InviterPeer) PeerConfig() (wireguard.PeerConfig, error) {
	if p.Version != inviterPeerVersion {
		return wireguard.PeerConfig{}, fmt.Errorf("invitation: unsupported inviter peer version %d", p.Version)
	}
	raw, err := base64.StdEncoding.DecodeString(p.PublicKey)
	if err != nil || len(raw) != 32 {
		return wireguard.PeerConfig{}, errors.New("invitation: invalid inviter peer public key")
	}
	allowed := make([]netip.Prefix, 0, len(p.AllowedIPs))
	for _, value := range p.AllowedIPs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return wireguard.PeerConfig{}, fmt.Errorf("invitation: invalid inviter peer allowedIP %q", value)
		}
		allowed = append(allowed, prefix)
	}
	if err := wireguard.ValidateAllowedIPs(allowed); err != nil {
		return wireguard.PeerConfig{}, fmt.Errorf("invitation: inviter peer: %w", err)
	}
	return wireguard.PeerConfig{PublicKey: raw, AllowedIPs: allowed, Endpoint: p.Endpoint}, nil
}

// SaveInviterPeer writes the inviter peer atomically with restrictive mode.
func SaveInviterPeer(path string, peer InviterPeer) error {
	raw, err := json.MarshalIndent(peer, "", "  ")
	if err != nil {
		return fmt.Errorf("invitation: encode inviter peer: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("invitation: inviter peer dir: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".inviter.json.*.tmp")
	if err != nil {
		return fmt.Errorf("invitation: inviter peer temp: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return fmt.Errorf("invitation: write inviter peer: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("invitation: install inviter peer: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

// LoadInviterPeers returns the persisted inviter peer as adapter
// configuration, or nil when no peer file exists.
func LoadInviterPeers(path string) ([]wireguard.PeerConfig, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("invitation: read inviter peer: %w", err)
	}
	var peer InviterPeer
	if err := json.Unmarshal(raw, &peer); err != nil {
		return nil, fmt.Errorf("invitation: decode inviter peer: %w", err)
	}
	config, err := peer.PeerConfig()
	if err != nil {
		return nil, err
	}
	return []wireguard.PeerConfig{config}, nil
}

// hubServiceBinder issues hub/net/bind through the real hub-server service SDK.
type hubServiceBinder struct {
	device *hubservice.DeviceKey
}

func (b hubServiceBinder) Bind(ctx context.Context, address any, id *identity.Identity, wireGuardKey, name string, admission protocol.DirectBootstrapResponse) (BindResult, error) {
	ready := make(chan struct{})
	var once sync.Once
	svc, err := hubconn.New(hubconn.Options{
		Address:  address,
		Identity: id,
		Name:     name,
		Device:   b.device,
		OnConnect: func(*channelgo.Sender) {
			once.Do(func() { close(ready) })
		},
	})
	if err != nil {
		return BindResult{}, err
	}
	if err := svc.Start(); err != nil {
		return BindResult{}, err
	}
	defer svc.Stop()
	select {
	case <-ready:
	case <-ctx.Done():
		return BindResult{}, ctx.Err()
	}
	body := protocol.AgentBindRequest{
		AgentProfileRegistration: protocol.AgentProfileRegistration{
			Version: protocol.WireVersion, WireGuardKey: wireGuardKey, Name: name,
			Platform: runtime.GOOS, OverlayAddresses: []string{},
			ConnectedAt: time.Now().UTC().Format(time.RFC3339Nano),
		},
		BindingKind: protocol.LocalAgentBindingJoin,
		Admission:   &admission,
	}
	registered, err := hubconn.SendTyped[bindResponse](svc, "hub/net/bind", body)
	if err != nil {
		return BindResult{}, err
	}
	if registered.Profile.Key == "" {
		return BindResult{}, errors.New("hub/net/bind returned no profile")
	}
	header, err := hubconn.OneValueTyped[hubHeader](ctx, svc, "hub/header", nil)
	if err != nil {
		return BindResult{}, err
	}
	return BindResult{
		HubKey:           registered.HubKey,
		HubNetworkID:     registered.HubNetworkId,
		OverlayAddresses: registered.Profile.OverlayAddresses,
		HeaderName:       header.Name,
	}, nil
}

// bindResponse mirrors the hub-server hub/net/bind reply (profile + hub signing
// identity).
type bindResponse struct {
	Success      bool                  `json:"success"`
	Profile      protocol.AgentProfile `json:"profile,omitempty"`
	HubKey       string                `json:"hubKey,omitempty"`
	HubNetworkId string                `json:"hubNetworkId,omitempty"`
}

// hubHeader is the hub/header stream value used for the display name.
type hubHeader struct {
	Name string `json:"name"`
}
