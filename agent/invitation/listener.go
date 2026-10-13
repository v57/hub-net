// Inviter direct bootstrap listener.
//
// The listener owns one UDP socket and plays two roles on it:
//
//  1. It accepts framed DirectBootstrapRequests from joiners, feeds them to
//     Inviter.Handle, and answers with a framed DirectBootstrapResponse (or a
//     framed protocol.NetworkError when the exchange fails).
//  2. It sends the inviter's invitation UDP probe to hub-net-node from the
//     same socket, so the node-observed endpoint delivered to the joiner in
//     the paired session is exactly the listener's address and port. Probe
//     responses are routed back to the pending probe waiter inside the read
//     loop, so the socket has exactly one reader.
//
// Garbage, oversized, and undecodable datagrams are dropped without a
// response so the listener cannot be used as a reflection amplifier. Frames
// with an invalid type are also dropped. Only a well-formed request that
// reaches Inviter.Handle can produce a response or error frame.
package invitation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	protocol "github.com/v57/hub-net-node/models"
	nodeprotocol "github.com/v57/hub-net-node/protocol"
)

const (
	defaultMaxConcurrent = 64
	defaultPerSource     = 8
	defaultHandleTimeout = 30 * time.Second
	defaultProbeTimeout  = 10 * time.Second
)

// Bootstrap error codes carried in error frames. Joiners map these to
// retry/abort decisions; the codes are part of the transport contract.
const (
	BootstrapErrorInvalid  = "bootstrap_request_invalid"
	BootstrapErrorReplay   = "bootstrap_replay"
	BootstrapErrorCapacity = "bootstrap_capacity"
	BootstrapErrorInternal = "bootstrap_internal"
)

// ListenerOptions configures the inviter direct bootstrap listener.
type ListenerOptions struct {
	// Inviter handles verified signed joiner requests. Required.
	Inviter *Inviter
	// Address is the UDP bind address. Empty defaults to ":0" (all interfaces,
	// ephemeral port).
	Address string
	// Logger receives listener lifecycle and exchange errors. Defaults to a
	// discard logger when nil.
	Logger *slog.Logger
	// MaxConcurrent bounds in-flight request handling. Defaults to 64.
	MaxConcurrent int
	// PerSource bounds in-flight requests per source IP. Defaults to 8.
	PerSource int
	// HandleTimeout bounds one Inviter.Handle call. Defaults to 30 seconds.
	HandleTimeout time.Duration
	// ProbeTimeout bounds one node probe round trip. Defaults to 10 seconds.
	ProbeTimeout time.Duration
}

// Listener is the inviter-side UDP endpoint for direct bootstrap exchanges.
type Listener struct {
	conn      *net.UDPConn
	inviter   *Inviter
	logger    *slog.Logger
	sem       chan struct{}
	perSource int
	handleTO  time.Duration
	probeTO   time.Duration

	mu         sync.Mutex
	perSourceN map[string]int
	probes     map[string]chan probeReply
	closed     bool
}

type probeReply struct {
	response nodeprotocol.UDPProbeResponse
	err      error
}

// NewListener binds the UDP socket. Call Run to serve.
func NewListener(options ListenerOptions) (*Listener, error) {
	if options.Inviter == nil {
		return nil, errors.New("invitation: bootstrap listener inviter required")
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	maxConcurrent := options.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrent
	}
	perSource := options.PerSource
	if perSource <= 0 {
		perSource = defaultPerSource
	}
	handleTO := options.HandleTimeout
	if handleTO <= 0 {
		handleTO = defaultHandleTimeout
	}
	probeTO := options.ProbeTimeout
	if probeTO <= 0 {
		probeTO = defaultProbeTimeout
	}
	address := options.Address
	if address == "" {
		address = ":0"
	}
	udpAddress, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("invitation: resolve bootstrap listener %q: %w", address, err)
	}
	conn, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return nil, fmt.Errorf("invitation: listen bootstrap udp %s: %w", address, err)
	}
	return &Listener{
		conn:       conn,
		inviter:    options.Inviter,
		logger:     logger,
		sem:        make(chan struct{}, maxConcurrent),
		perSource:  perSource,
		handleTO:   handleTO,
		probeTO:    probeTO,
		perSourceN: make(map[string]int),
		probes:     make(map[string]chan probeReply),
	}, nil
}

// Addr returns the bound UDP address.
func (l *Listener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// Close closes the socket. Idempotent.
func (l *Listener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return l.conn.Close()
}

// Probe sends the invitation UDP probe from the listener socket and waits for
// the node's confirmation. The node records the datagram source as the
// inviter's observed endpoint, so this must come from the same socket that
// accepts direct bootstrap requests. expectedTicketID is the node's
// UDPProbeResponse.TicketID (token digest + ":" + service key).
func (l *Listener) Probe(ctx context.Context, nodeEndpoint string, probe nodeprotocol.InvitationUDPProbe, expectedTicketID string) error {
	target, err := net.ResolveUDPAddr("udp", nodeEndpoint)
	if err != nil {
		return fmt.Errorf("invitation: resolve node probe endpoint %q: %w", nodeEndpoint, err)
	}
	body, err := json.Marshal(probe)
	if err != nil {
		return fmt.Errorf("invitation: encode probe: %w", err)
	}
	waiter := make(chan probeReply, 1)
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return errors.New("invitation: bootstrap listener closed")
	}
	l.probes[expectedTicketID] = waiter
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		delete(l.probes, expectedTicketID)
		l.mu.Unlock()
	}()

	if _, err := l.conn.WriteToUDP(body, target); err != nil {
		return fmt.Errorf("invitation: write node probe: %w", err)
	}
	timer := time.NewTimer(l.probeTO)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case reply := <-waiter:
		return reply.err
	case <-timer.C:
		return fmt.Errorf("invitation: node probe timed out after %s", l.probeTO)
	}
}

// Run serves datagrams until ctx is cancelled or the listener is closed.
func (l *Listener) Run(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = l.conn.Close() })
	defer stop()
	buffer := make([]byte, MaxBootstrapFrameBytes+1)
	for {
		n, address, err := l.conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || l.isClosed() {
				return nil
			}
			return err
		}
		data := append([]byte(nil), buffer[:n]...)
		if len(data) >= 4 && string(data[0:4]) == frameMagic {
			l.dispatchFrame(ctx, address, data)
			continue
		}
		l.routeProbeResponse(data)
	}
}

func (l *Listener) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

func (l *Listener) routeProbeResponse(data []byte) {
	var response nodeprotocol.UDPProbeResponse
	if err := json.Unmarshal(data, &response); err != nil || response.Version != protocol.WireVersion || response.TicketID == "" {
		return
	}
	l.mu.Lock()
	waiter, ok := l.probes[response.TicketID]
	l.mu.Unlock()
	if !ok {
		return
	}
	select {
	case waiter <- probeReply{response: response}:
	default:
	}
}

func (l *Listener) dispatchFrame(ctx context.Context, address *net.UDPAddr, data []byte) {
	parsed, err := unmarshalFrame(data)
	if err != nil {
		// Malformed frames get no reply (no reflection amplification).
		l.logger.Debug("drop malformed bootstrap frame", slog.String("err", err.Error()))
		return
	}
	if parsed.Type != FrameRequest {
		// Only request frames are valid inbound traffic.
		return
	}
	request, err := decodeRequestPayload(parsed.Payload)
	if err != nil {
		l.writeError(address, parsed.RequestID, bootstrapNetworkError(fmt.Errorf("%w: %v", ErrBootstrapRequest, err)))
		return
	}
	select {
	case l.sem <- struct{}{}:
	default:
		// Backpressure: drop instead of queueing; joiners retry on timeout.
		return
	}
	if !l.acquireSource(address) {
		<-l.sem
		return
	}
	go l.handle(ctx, address, parsed.RequestID, request)
}

func (l *Listener) acquireSource(address *net.UDPAddr) bool {
	source := address.IP.String()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perSourceN[source] >= l.perSource {
		return false
	}
	l.perSourceN[source]++
	return true
}

func (l *Listener) releaseSource(address *net.UDPAddr) {
	source := address.IP.String()
	l.mu.Lock()
	if l.perSourceN[source] <= 1 {
		delete(l.perSourceN, source)
	} else {
		l.perSourceN[source]--
	}
	l.mu.Unlock()
}

func (l *Listener) handle(ctx context.Context, address *net.UDPAddr, requestID [requestIDLen]byte, request protocol.DirectBootstrapRequest) {
	defer func() {
		<-l.sem
		l.releaseSource(address)
	}()
	handleCtx, cancel := context.WithTimeout(ctx, l.handleTO)
	defer cancel()
	response, err := l.inviter.Handle(handleCtx, request)
	if err != nil {
		l.logger.Info("bootstrap request rejected", slog.String("from", address.String()), slog.String("err", err.Error()))
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		l.writeError(address, requestID, bootstrapNetworkError(err))
		return
	}
	l.logger.Info("bootstrap request answered", slog.String("from", address.String()))
	payload, err := encodeResponsePayload(response)
	if err != nil {
		l.writeError(address, requestID, bootstrapNetworkError(err))
		return
	}
	out, err := marshalFrame(FrameResponse, requestID, payload)
	if err != nil {
		l.logger.Error("encode bootstrap response frame", slog.String("err", err.Error()))
		return
	}
	if _, err := l.conn.WriteToUDP(out, address); err != nil {
		l.logger.Warn("write bootstrap response", slog.String("err", err.Error()))
	}
}

func (l *Listener) writeError(address *net.UDPAddr, requestID [requestIDLen]byte, networkError *protocol.NetworkError) {
	payload, err := json.Marshal(networkError)
	if err != nil {
		l.logger.Error("encode bootstrap error", slog.String("err", err.Error()))
		return
	}
	out, err := marshalFrame(FrameError, requestID, payload)
	if err != nil {
		l.logger.Error("encode bootstrap error frame", slog.String("err", err.Error()))
		return
	}
	if _, err := l.conn.WriteToUDP(out, address); err != nil {
		l.logger.Warn("write bootstrap error", slog.String("err", err.Error()))
	}
}

// bootstrapNetworkError maps an inviter handler error to the wire-shaped
// NetworkError carried in an error frame.
func bootstrapNetworkError(err error) *protocol.NetworkError {
	code := BootstrapErrorInternal
	retryable := true
	switch {
	case errors.Is(err, ErrBootstrapRequest):
		code, retryable = BootstrapErrorInvalid, false
	case errors.Is(err, ErrBootstrapReplay):
		code, retryable = BootstrapErrorReplay, false
	case errors.Is(err, ErrBootstrapCapacity):
		code, retryable = BootstrapErrorCapacity, true
	}
	return &protocol.NetworkError{
		Version:   protocol.WireVersion,
		Code:      code,
		Message:   err.Error(),
		Retryable: retryable,
	}
}
