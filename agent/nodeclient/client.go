// Package nodeclient maintains the agent's persistent online-inviter
// registration with hub-net-node.
//
// Registration is keyed by the agent's service public key (the same key that
// signs its compact invitations) and proves possession of the matching
// Ed25519 private key through the node's signed challenge handshake:
//
//	inviter.register (service key only) -> inviter.challenge
//	-> inviter.register (nonce + signature) -> inviter.registered
//
// While the registration lease is live and the WebSocket stays open the agent
// is considered online, so a joiner's session.open carrying one of its
// invitations is accepted. The client refreshes the lease before expiry and
// reconnects with bounded backoff on failure. The node never relays
// application traffic; this client only proves presence.
package nodeclient

import (
	"context"
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
	"strings"
	"sync"
	"time"

	"github.com/v57/hub-net-node/protocol"
	"github.com/v57/hub-service-go/identity"
	hubprotocol "github.com/v57/hub-service-go/protocol"
)

const (
	defaultLeeway         = 30 * time.Second
	defaultInitialBackoff = time.Second
	defaultMaxBackoff     = 30 * time.Second
	handshakeTimeout      = 15 * time.Second
	bootstrapTimeout      = 45 * time.Second
)

// BootstrapEvent carries the outcome of one direct-bootstrap rendezvous after
// a joiner opens a session with one of this agent's invitations. The node
// pairs the joiner with the online inviter and relays only coordination data:
// the joiner's declared candidates and its node-observed endpoint.
type BootstrapEvent struct {
	// TokenDigest is the invitation replay id (SHA-256 of the exact payload)
	// the joiner presented.
	TokenDigest string
	// TransactionID is the joiner's transaction identity for the join.
	TransactionID string
	// TunnelInstanceID and Generation are the joiner's tunnel identity, empty
	// and zero for machine joins.
	TunnelInstanceID string
	Generation       uint64
	// JoinerKey is the joiner's service public key.
	JoinerKey string
	// SessionID is this inviter's rendezvous session id.
	SessionID string
	// Candidates are the joiner's declared direct candidates.
	Candidates []hubprotocol.Candidate
	// Observed is the joiner's node-observed endpoint.
	Observed protocol.ObservedEndpoint
}

// BootstrapHandler receives each direct-bootstrap rendezvous the node signals
// to this online inviter.
type BootstrapHandler func(BootstrapEvent)

// Options configures the node registration client.
type Options struct {
	// Endpoint returns the current hub-net-node rendezvous endpoint. The value
	// may be a bare host:port or carry an explicit scheme/path (for example
	// "hub.v57.dev/node"); the stored default has no implicit scheme. Empty
	// disables registration until an endpoint is available.
	Endpoint func() string
	// Identity is the agent's service identity. Its public key is registered;
	// its private key signs the node's challenge.
	Identity *identity.Identity
	// Logger receives registration lifecycle events. Defaults to a discard
	// logger when nil.
	Logger *slog.Logger
	// Now is the clock used for lease scheduling. Defaults to time.Now.
	Now func() time.Time
	// Leeway is how early the registration lease is refreshed before expiry.
	// Defaults to 30 seconds.
	Leeway time.Duration
	// InitialBackoff is the first reconnect delay after a failure. Defaults to
	// one second.
	InitialBackoff time.Duration
	// MaxBackoff caps the reconnect delay. Defaults to 30 seconds.
	MaxBackoff time.Duration
	// Dial is a test hook for the WebSocket transport. Defaults to a minimal
	// RFC 6455 client speaking the node's envelope protocol.
	Dial func(ctx context.Context, endpoint string) (net.Conn, error)
	// Bootstrap receives the joiner's direct candidates for each invitation
	// bootstrap the node signals. May be nil to discard the exchange; the
	// client still participates in the rendezvous session.
	Bootstrap BootstrapHandler
	// Pending is told about each join the node signals (inviter.bootstrap),
	// as soon as the signal arrives: the invitation replay id and the
	// joiner's session key. The inviter answers direct bootstrap requests
	// only for signalled joins.
	Pending func(tokenDigest, joinerKey string)
	// Candidates returns the inviter's declared WireGuard UDP candidates to
	// offer once its bootstrap session opens. May be nil or return nil; the
	// node still delivers the inviter's node-observed endpoint to the joiner.
	Candidates func() []hubprotocol.Candidate
	// Probe sends the invitation UDP probe and awaits the node's confirmation.
	// When set, the client builds the probe from the pending envelope and
	// delegates the datagram to this hook instead of dialing its own ephemeral
	// UDP socket. The agent wires a persistent bootstrap listener here so the
	// node-observed endpoint it records is the listener's address:port, which
	// is exactly where the joiner sends the framed direct bootstrap request.
	Probe func(ctx context.Context, nodeEndpoint string, probe protocol.InvitationUDPProbe, expectedTicketID string) error
}

// Client tracks one persistent online-inviter registration. Construct with
// New and run with Run; Online reports whether the lease is currently live.
type Client struct {
	opts       Options
	log        *slog.Logger
	now        func() time.Time
	leeway     time.Duration
	backoff    time.Duration
	maxBack    time.Duration
	key        string
	priv       ed25519.PrivateKey
	dial       func(ctx context.Context, endpoint string) (net.Conn, error)
	bootstrap  BootstrapHandler
	candidates func() []hubprotocol.Candidate
	probe      func(ctx context.Context, nodeEndpoint string, probe protocol.InvitationUDPProbe, expectedTicketID string) error
	mu         sync.RWMutex
	online     bool
	endpoint   string
	started    bool
}

// New validates options and constructs a Client.
func New(options Options) (*Client, error) {
	if options.Identity == nil {
		return nil, errors.New("nodeclient: identity required")
	}
	key, err := options.Identity.PublicKeyBase64()
	if err != nil {
		return nil, fmt.Errorf("nodeclient: service key: %w", err)
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	leeway := options.Leeway
	if leeway <= 0 {
		leeway = defaultLeeway
	}
	initial := options.InitialBackoff
	if initial <= 0 {
		initial = defaultInitialBackoff
	}
	max := options.MaxBackoff
	if max <= 0 {
		max = defaultMaxBackoff
	}
	if max < initial {
		max = initial
	}
	dial := options.Dial
	if dial == nil {
		dial = DialWebSocket
	}
	return &Client{
		opts:       options,
		log:        logger,
		now:        now,
		leeway:     leeway,
		backoff:    initial,
		maxBack:    max,
		key:        key,
		priv:       options.Identity.PrivateKey(),
		dial:       dial,
		bootstrap:  options.Bootstrap,
		candidates: options.Candidates,
		probe:      options.Probe,
	}, nil
}

// Online reports whether the agent currently holds a live registration.
func (c *Client) Online() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.online
}

// Endpoint returns the last endpoint the client dialed, or "" before any
// attempt.
func (c *Client) Endpoint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.endpoint
}

// Run registers the agent and keeps the registration alive until ctx is
// cancelled. It returns nil on cancellation and the last registration error
// when the loop gives up; under normal operation it only returns on ctx
// cancellation.
func (c *Client) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("nodeclient: already started")
	}
	c.started = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.started = false
		c.online = false
		c.mu.Unlock()
	}()

	backoff := c.backoff
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		endpoint := strings.TrimSpace(c.endpointProvider())
		if endpoint == "" {
			c.setOnline(false)
			if !wait(ctx, backoff) {
				return nil
			}
			continue
		}
		c.setEndpoint(endpoint)
		err := c.connectAndRegister(ctx, endpoint)
		c.setOnline(false)
		if err == nil {
			backoff = c.backoff
			continue
		}
		if errors.Is(err, context.Canceled) {
			return nil
		}
		c.log.Warn("node registration failed",
			slog.String("endpoint", endpoint),
			slog.String("err", err.Error()),
			slog.Duration("retryIn", backoff))
		if !wait(ctx, backoff) {
			return nil
		}
		backoff *= 2
		if backoff > c.maxBack {
			backoff = c.maxBack
		}
	}
}

func (c *Client) endpointProvider() string {
	if c.opts.Endpoint != nil {
		return c.opts.Endpoint()
	}
	return ""
}

// connectAndRegister performs one registration handshake and then maintains
// the lease until the connection drops or the context is cancelled.
func (c *Client) connectAndRegister(ctx context.Context, endpoint string) error {
	conn, err := c.dial(ctx, endpoint)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	defer conn.Close()
	// Unblock the read loop on cancellation so Run returns promptly.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	expiresAt, err := c.register(ctx, conn)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	c.setOnline(true)
	c.log.Info("node registration live",
		slog.String("endpoint", endpoint),
		slog.Time("expiresAt", expiresAt))
	for {
		refreshAt := expiresAt.Add(-c.leeway)
		if !refreshAt.After(c.now()) {
			refreshAt = c.now().Add(time.Second)
		}
		_ = conn.SetReadDeadline(refreshAt)
		reply, err := ReadEnvelope(conn)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				expiresAt, err = c.register(ctx, conn)
				if err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					return err
				}
				continue
			}
			return err
		}
		switch reply.Type {
		case protocol.MessageInviterUnregistered:
			c.log.Warn("node dropped registration; re-registering")
			expiresAt, err = c.register(ctx, conn)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
		case protocol.MessageBootstrapPending:
			if err := c.runBootstrap(ctx, conn, endpoint, reply); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				c.log.Warn("inviter bootstrap exchange failed",
					slog.String("endpoint", endpoint),
					slog.String("err", err.Error()))
			}
		case protocol.MessageError:
			if reply.Error == nil {
				return errors.New("node error without details")
			}
			return fmt.Errorf("node error: %s %s", reply.Error.Code, reply.Error.Message)
		default:
			// Ignore forward-compatible pushes unrelated to the exchange in
			// progress.
		}
	}
}

// runBootstrap participates in one direct-bootstrap rendezvous on the
// registration connection: the node signaled that a joiner opened a session
// with one of this agent's invitations, so the client probes, opens its own
// side of the paired session, offers the inviter's declared candidates, and
// reports the joiner's candidates to the Bootstrap handler.
func (c *Client) runBootstrap(ctx context.Context, conn net.Conn, endpoint string, pending protocol.Envelope) error {
	if pending.InvitationCode == "" || pending.Key == "" ||
		pending.TokenDigest == "" || pending.TransactionID == "" {
		return errors.New("nodeclient: incomplete inviter.bootstrap signal")
	}
	if c.opts.Pending != nil {
		c.opts.Pending(pending.TokenDigest, pending.Key)
	}
	if err := c.sendProbe(ctx, endpoint, pending); err != nil {
		return err
	}
	openRequestID := newRequestID()
	if err := WriteEnvelope(conn, protocol.Envelope{
		MajorVersion:   protocol.MajorVersion,
		MinorVersion:   protocol.MinorVersion,
		Type:           protocol.MessageOpenSession,
		RequestID:      openRequestID,
		InvitationCode: pending.InvitationCode,
		Key:            c.key,
		TokenDigest:    pending.TokenDigest,
		TransactionID:  pending.TransactionID,
		TunnelInstance: pending.TunnelInstance,
		Generation:     pending.Generation,
	}); err != nil {
		return fmt.Errorf("nodeclient: open bootstrap session: %w", err)
	}

	var sessionID string
	for {
		_ = conn.SetReadDeadline(c.now().Add(handshakeTimeout))
		reply, err := ReadEnvelope(conn)
		if err != nil {
			return fmt.Errorf("nodeclient: read bootstrap open: %w", err)
		}
		if reply.Type == protocol.MessageError {
			if reply.Error == nil {
				return errors.New("nodeclient: bootstrap open error without details")
			}
			return fmt.Errorf("nodeclient: bootstrap open rejected: %s %s",
				reply.Error.Code, reply.Error.Message)
		}
		if reply.Type != protocol.MessageSessionOpened || reply.RequestID != openRequestID || reply.SessionID == "" {
			continue
		}
		sessionID = reply.SessionID
		break
	}
	// Release the paired session on the registration connection once this
	// exchange finishes, whether it succeeds or fails. Without this the node
	// keeps state.sessionID set on the registration connection and rejects the
	// next session.open with "session already open", breaking joins after the
	// first exchange. The close is best-effort: the session also expires
	// server-side.
	defer c.closeBootstrapSession(conn, sessionID)

	// Offer the inviter's declared candidates so the joiner learns a reachable
	// endpoint. The node also pushes the inviter's observed endpoint to the
	// joiner when the sessions pair.
	if c.candidates != nil {
		for _, candidate := range c.candidates() {
			candidate.Version = hubprotocol.WireVersion
			candidate.SessionID = sessionID
			candidate.Key = c.key
			candidate.Transport = "udp"
			if candidate.ExpiresAt == "" {
				candidate.ExpiresAt = c.now().Add(protocol.DefaultCandidateLifetime).UTC().Format(time.RFC3339Nano)
			}
			if err := WriteEnvelope(conn, protocol.Envelope{
				MajorVersion: protocol.MajorVersion,
				MinorVersion: protocol.MinorVersion,
				Type:         protocol.MessageOfferCandidate,
				SessionID:    sessionID,
				Candidate:    &candidate,
			}); err != nil {
				return fmt.Errorf("nodeclient: offer candidate: %w", err)
			}
		}
	}

	// Wait for the joiner's candidates and observed endpoint. The joiner may
	// have offered before this session opened; the node delivers them on
	// pairing, or pushes them when the offer arrives. The wait is bounded by
	// the bootstrap exchange window; an observed-only list is reported once
	// the window closes so the exchange never blocks registration forever.
	_ = conn.SetReadDeadline(c.now().Add(bootstrapTimeout))
	var event BootstrapEvent
	seen := false
waitLoop:
	for {
		reply, err := ReadEnvelope(conn)
		if err != nil {
			if seen {
				break
			}
			return fmt.Errorf("nodeclient: read joiner candidates: %w", err)
		}
		switch reply.Type {
		case protocol.MessageCandidates:
			if reply.SessionID != sessionID {
				continue
			}
			event = BootstrapEvent{
				TokenDigest:      pending.TokenDigest,
				TransactionID:    pending.TransactionID,
				TunnelInstanceID: pending.TunnelInstance,
				Generation:       pending.Generation,
				JoinerKey:        pending.Key,
				SessionID:        sessionID,
				Candidates:       reply.Candidates,
			}
			if reply.Observed != nil {
				event.Observed = *reply.Observed
			}
			seen = true
			if len(event.Candidates) > 0 {
				break waitLoop
			}
		case protocol.MessageError:
			if reply.Error == nil {
				return errors.New("nodeclient: bootstrap error without details")
			}
			return fmt.Errorf("nodeclient: bootstrap rejected: %s %s",
				reply.Error.Code, reply.Error.Message)
		default:
			// Registration traffic or another peer's exchange; keep waiting.
		}
	}
	if seen && c.bootstrap != nil {
		c.bootstrap(event)
	}
	return nil
}

// closeBootstrapSession releases the paired bootstrap session on the
// registration connection so a subsequent inviter.bootstrap push can open its
// own side again. Without this the node keeps state.sessionID set on the
// registration connection and rejects the next session.open with "session
// already open", breaking joins after the first exchange. The close is
// best-effort: the session also expires server-side.
func (c *Client) closeBootstrapSession(conn net.Conn, sessionID string) {
	_ = WriteEnvelope(conn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion,
		MinorVersion: protocol.MinorVersion,
		Type:         protocol.MessageCloseSession,
		SessionID:    sessionID,
	})
}

// sendProbe sends the invitation UDP probe to the node so the inviter's own
// session open carries a node-observed endpoint for the joiner. It delegates
// to the configured Probe hook when one is set, so a persistent bootstrap
// listener can own the socket; otherwise it dials an ephemeral socket. The
// probe response is validated against this inviter's key, proving the node
// recorded the observation for the right identity.
func (c *Client) sendProbe(ctx context.Context, endpoint string, pending protocol.Envelope) error {
	target, err := normalizeEndpoint(endpoint)
	if err != nil {
		return err
	}
	probe := protocol.InvitationUDPProbe{
		Version:          hubprotocol.WireVersion,
		InvitationCode:   pending.InvitationCode,
		Key:              c.key,
		TokenDigest:      pending.TokenDigest,
		TransactionID:    pending.TransactionID,
		TunnelInstanceID: pending.TunnelInstance,
		Generation:       pending.Generation,
	}
	expectedTicketID := pending.TokenDigest + ":" + c.key
	if c.probe != nil {
		return c.probe(ctx, target.Host, probe, expectedTicketID)
	}
	remote, err := net.ResolveUDPAddr("udp", target.Host)
	if err != nil {
		return fmt.Errorf("nodeclient: resolve node udp endpoint: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return fmt.Errorf("nodeclient: dial node udp endpoint: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(c.now().Add(handshakeTimeout))
	body, err := json.Marshal(probe)
	if err != nil {
		return err
	}
	if _, err := conn.Write(body); err != nil {
		return fmt.Errorf("nodeclient: write invitation probe: %w", err)
	}
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return fmt.Errorf("nodeclient: read invitation probe response: %w", err)
	}
	var reply protocol.UDPProbeResponse
	if err := json.Unmarshal(response[:n], &reply); err != nil {
		return fmt.Errorf("nodeclient: decode probe response: %w", err)
	}
	if reply.Version != hubprotocol.WireVersion || reply.TicketID != expectedTicketID {
		return errors.New("nodeclient: probe response does not match inviter ticket")
	}
	return nil
}

// register runs the signed challenge handshake once and returns the lease
// expiry reported by the node.
func (c *Client) register(ctx context.Context, conn net.Conn) (time.Time, error) {
	challengeRequestID := newRequestID()
	if err := WriteEnvelope(conn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion,
		MinorVersion: protocol.MinorVersion,
		Type:         protocol.MessageRegisterInviter,
		RequestID:    challengeRequestID,
		ServiceKey:   c.key,
	}); err != nil {
		return time.Time{}, fmt.Errorf("nodeclient: request challenge: %w", err)
	}

	var nonce string
	for {
		_ = conn.SetReadDeadline(c.now().Add(handshakeTimeout))
		reply, err := ReadEnvelope(conn)
		if err != nil {
			return time.Time{}, fmt.Errorf("nodeclient: read challenge: %w", err)
		}
		if reply.Type == protocol.MessageError {
			if reply.Error == nil {
				return time.Time{}, errors.New("nodeclient: challenge error without details")
			}
			return time.Time{}, fmt.Errorf("nodeclient: challenge rejected: %s %s",
				reply.Error.Code, reply.Error.Message)
		}
		if reply.RequestID != challengeRequestID {
			continue
		}
		if reply.Type != protocol.MessageInviterChallenge || reply.ChallengeNonce == "" {
			return time.Time{}, fmt.Errorf("nodeclient: unexpected reply %q", reply.Type)
		}
		nonce = reply.ChallengeNonce
		break
	}

	nonceBytes, err := decodeNonce(nonce)
	if err != nil {
		return time.Time{}, err
	}
	signature, err := hubprotocol.SignBytes(hubprotocol.PurposeInviterRegistration, nonceBytes, c.priv)
	if err != nil {
		return time.Time{}, fmt.Errorf("nodeclient: sign challenge: %w", err)
	}

	answerRequestID := newRequestID()
	if err := WriteEnvelope(conn, protocol.Envelope{
		MajorVersion:       protocol.MajorVersion,
		MinorVersion:       protocol.MinorVersion,
		Type:               protocol.MessageRegisterInviter,
		RequestID:          answerRequestID,
		ServiceKey:         c.key,
		ChallengeNonce:     nonce,
		ChallengeSignature: signature,
	}); err != nil {
		return time.Time{}, fmt.Errorf("nodeclient: answer challenge: %w", err)
	}

	for {
		_ = conn.SetReadDeadline(c.now().Add(handshakeTimeout))
		reply, err := ReadEnvelope(conn)
		if err != nil {
			return time.Time{}, fmt.Errorf("nodeclient: read registration: %w", err)
		}
		if reply.Type == protocol.MessageError {
			if reply.Error == nil {
				return time.Time{}, errors.New("nodeclient: registration error without details")
			}
			return time.Time{}, fmt.Errorf("nodeclient: registration rejected: %s %s",
				reply.Error.Code, reply.Error.Message)
		}
		if reply.RequestID != answerRequestID {
			continue
		}
		if reply.Type != protocol.MessageInviterRegistered || reply.RegistrationExpiresAt == "" {
			return time.Time{}, fmt.Errorf("nodeclient: unexpected reply %q", reply.Type)
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, reply.RegistrationExpiresAt)
		if err != nil {
			return time.Time{}, fmt.Errorf("nodeclient: parse lease expiry: %w", err)
		}
		return expiresAt, nil
	}
}

func (c *Client) setOnline(online bool) {
	c.mu.Lock()
	c.online = online
	c.mu.Unlock()
}

func (c *Client) setEndpoint(endpoint string) {
	c.mu.Lock()
	c.endpoint = endpoint
	c.mu.Unlock()
}

func decodeNonce(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	decoded, err = base64.URLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: decode challenge nonce: %w", err)
	}
	return decoded, nil
}

func newRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("nodeclient-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value[:])
}

func wait(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
