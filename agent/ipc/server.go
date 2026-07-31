// server.go implements the local IPC transport: an HTTP server bound to a
// Unix-domain socket. The hub-service-go Publisher (and the Bun/Swift
// clients) POST JSON to /challenge, /attest, /status over the socket; this
// file decodes those requests, dispatches to the Handler, and writes the
// wire-level response or error envelope.
//
// Security model (PLATFORMS.md):
//
//   - The socket is created with a restrictive mode; the platform installer
//     sets directory ownership and group so only the agent user and authorized
//     service accounts may connect.
//   - Peer credentials are checked (peers.go) so that, even with filesystem
//     access, a connection from an unexpected local uid is rejected before
//     the request reaches the Handler.
//   - Nonce freshness and service signatures are enforced by the Handler
//     (attest.go); filesystem access alone is never a service identity proof.
//
// The server removes the socket file on shutdown so PLATFORMS.md cleanup
// invariant holds even after a crash that left a stale socket behind.
package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// MaxRequestBytes bounds a single IPC request body. Requests carry short
// JSON envelopes (keys, share names, signatures); a larger body indicates a
// malformed or hostile client.
const MaxRequestBytes = 64 * 1024

// ReadTimeout bounds how long the server waits for the full request body.
const ReadTimeout = 5 * time.Second

// WriteTimeout bounds response writes. Attestation signing is sub-millisecond,
// so this only fires under pathological load.
const WriteTimeout = 5 * time.Second

// ShutdownTimeout bounds a graceful Close before in-flight requests are
// cancelled.
const ShutdownTimeout = 5 * time.Second

// ServerOptions configure a socket-bound IPC Server.
type ServerOptions struct {
	// SocketPath is the Unix-domain socket path. Required.
	SocketPath string
	// Handler serves IPC requests. Required.
	Handler Handler
	// Logger receives lifecycle and error events. Defaults to slog.Default.
	Logger *slog.Logger
	// PeerPolicy controls local-client enforcement. Defaults to a policy
	// that requires peer credentials to match the agent uid (AllowAnyLocal
	// false). Production callers leave the default; tests may relax it.
	PeerPolicy PeerPolicy
	// SocketMode is the mode applied to the created socket file. Defaults
	// to 0o660: PLATFORMS.md specifies 0660 with root ownership and a
	// restricted group.
	SocketMode os.FileMode
}

// Server is the socket-bound local IPC server. Construct with NewServer and
// run with Start (blocking) or Serve (in a goroutine).
type Server struct {
	opts         ServerOptions
	logger       *slog.Logger
	httpServer   *http.Server
	listener     net.Listener
	peerListener *peerConnListener
	mu           sync.Mutex
	started      bool
	closed       bool
}

// NewServer constructs a socket-bound Server. The socket is bound
// synchronously: on success Addr() is immediately valid, so callers (and
// tests) can connect without polling for readiness. SocketPath and Handler
// are required; sensible defaults are applied for the remaining fields.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.SocketPath == "" {
		return nil, errors.New("ipc: SocketPath required")
	}
	if opts.Handler == nil {
		return nil, errors.New("ipc: Handler required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	mode := opts.SocketMode
	if mode == 0 {
		mode = 0o660
	}
	policy := opts.PeerPolicy
	if policy.AllowAnyLocal == false && policy.ExpectedUID == nil && policy.RootOK == false {
		// Default: require the connecting peer to share the agent uid.
		// Callers that have already restricted the socket via filesystem
		// permissions may pass AllowAnyLocal = true to skip the check.
		policy.ExpectedUID = ptrInt(os.Getuid())
		policy.RootOK = true
	}

	// Remove any stale socket file from a prior crash before binding.
	if err := os.Remove(opts.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("ipc: remove stale socket %s: %w", opts.SocketPath, err)
	}
	listener, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen unix %s: %w", opts.SocketPath, err)
	}
	if err := os.Chmod(opts.SocketPath, mode); err != nil {
		_ = listener.Close()
		_ = os.Remove(opts.SocketPath)
		return nil, fmt.Errorf("ipc: chmod socket %s: %w", opts.SocketPath, err)
	}
	// Wrap so peer credentials are read once per accepted connection and
	// surfaced to handlers via the request context.
	peerListener := newPeerConnListener(listener)

	mux := http.NewServeMux()
	server := &Server{opts: ServerOptions{
		SocketPath: opts.SocketPath,
		Handler:    opts.Handler,
		Logger:     logger,
		PeerPolicy: policy,
		SocketMode: mode,
	}, logger: logger, listener: listener, peerListener: peerListener}
	mux.HandleFunc("/challenge", server.handleChallenge)
	mux.HandleFunc("/attest", server.handleAttest)
	mux.HandleFunc("/status", server.handleStatus)
	mux.HandleFunc("/binding/proof", server.handleBindingProof)
	mux.HandleFunc("/", server.handleUnknown)
	server.httpServer = &http.Server{
		Handler:     http.HandlerFunc(server.withPeerCheck(mux.ServeHTTP)),
		ConnContext: peerListener.connContext,
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				peerListener.forget(conn)
			}
		},
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
	}
	logger.Info("ipc server listening",
		slog.String("socket", opts.SocketPath),
		slog.String("mode", fmt.Sprintf("%o", mode)),
	)
	return server, nil
}

// SocketPath returns the configured socket path.
func (s *Server) SocketPath() string { return s.opts.SocketPath }

// Addr returns the resolved listener address. Valid immediately after
// NewServer because the socket is bound synchronously.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Serve accepts connections until ctx is cancelled, Close is called, or the
// listener returns a fatal error. The socket is already bound by NewServer;
// Serve only runs the accept loop. Serve is the blocking entry point;
// callers that want concurrency should use Start.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("ipc: server already started")
	}
	if s.closed {
		s.mu.Unlock()
		return errors.New("ipc: server closed")
	}
	s.started = true
	s.mu.Unlock()

	serveErr := make(chan error, 1)
	go func() { serveErr <- s.httpServer.Serve(s.peerListener) }()

	select {
	case <-ctx.Done():
		return s.Close(context.Background())
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		s.cleanupSocket()
		return err
	}
}

// Start is a non-blocking alias of Serve that runs in a goroutine and
// returns the first fatal error on the returned channel. The channel also
// closes when the server stops cleanly.
func (s *Server) Start(ctx context.Context) <-chan error {
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		if err := s.Serve(ctx); err != nil {
			errs <- err
		}
	}()
	return errs
}

// Close stops the HTTP server, removes the socket file, and frees the
// listener. Safe to call multiple times.
func (s *Server) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	shutdownCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		shutdownCtx, cancel = context.WithTimeout(ctx, ShutdownTimeout)
		defer cancel()
	}
	err := s.httpServer.Shutdown(shutdownCtx)
	s.cleanupSocket()
	return err
}

// cleanupSocket removes the socket file. PLATFORMS.md requires interface,
// route, DNS, and socket artifacts to be removed on shutdown.
func (s *Server) cleanupSocket() {
	s.mu.Lock()
	s.listener = nil
	s.mu.Unlock()
	if err := os.Remove(s.opts.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.logger.Warn("ipc socket cleanup failed",
			slog.String("socket", s.opts.SocketPath),
			slog.String("err", err.Error()),
		)
	}
}

// withPeerCheck wraps next so that each connection's peer credentials are
// verified before the request is dispatched.
func (s *Server) withPeerCheck(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := VerifyLocalPeer(r, s.opts.PeerPolicy); err != nil {
			s.logger.Warn("ipc peer rejected",
				slog.String("remote", r.RemoteAddr),
				slog.String("err", err.Error()),
			)
			writeError(w, http.StatusForbidden, "peer_rejected", err.Error())
			return
		}
		next(w, r)
	}
}

// handleChallenge serves POST /challenge.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req ChallengeRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	resp, err := s.opts.Handler.Challenge(req)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	if resp.Type == "" {
		resp.Type = MessageAttestResponse
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAttest serves POST /attest. The response body is the bare
// AgentAttestation object (flat, no envelope) so the Bun, Swift, and Go SDK
// clients can json.Unmarshal the payload directly into their attestation
// model. The Handler's AttestResponse wrapper is for in-process callers.
func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req AttestRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	resp, err := s.opts.Handler.Attest(req)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp.Attestation)
}

// handleStatus serves GET/POST /status.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
		return
	}
	var req StatusRequest
	// Body is optional for GET and for POSTs without content.
	if r.ContentLength != 0 && r.Method == http.MethodPost {
		if err := decodeRequest(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	}
	resp, err := s.opts.Handler.Status(req)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	if resp.Type == "" {
		resp.Type = MessageStatusRequest
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBindingProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var req BindingProofRequest
	if err := decodeRequest(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	resp, err := s.opts.Handler.BindingProof(req)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleUnknown rejects unmatched paths. The Publisher only hits the three
// documented routes; anything else is a misconfigured client or a probe.
func (s *Server) handleUnknown(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "unknown_path", "no handler for "+r.URL.Path)
}

// decodeRequest reads and JSON-decodes the body into target, enforcing the
// request size cap.
func decodeRequest(r *http.Request, target any) error {
	reader := http.MaxBytesReader(nil, r.Body, MaxRequestBytes)
	defer reader.Close()
	dec := json.NewDecoder(reader)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty request body")
		}
		return err
	}
	return nil
}

// writeHandlerError maps an ipc error (carrying a wire code via Code()) onto
// an HTTP status and the structured error envelope. Unknown errors fall back
// to 500.
func writeHandlerError(w http.ResponseWriter, err error) {
	var ipcErr *ipcError
	if errors.As(err, &ipcErr) {
		writeError(w, statusForCode(ipcErr.Code()), ipcErr.Code(), ipcErr.Error())
		return
	}
	writeError(w, http.StatusInternalServerError, "agent_unavailable", err.Error())
}

// statusForCode maps a wire error code to an HTTP status. The body carries
// the code verbatim so clients can branch on it; the status is for transport
// correctness and for the simple clients that only inspect the status.
func statusForCode(code string) int {
	switch code {
	case "invalid_request", "invalid_nonce", "invalid_signature":
		return http.StatusBadRequest
	case "forbidden", "remote_target":
		return http.StatusForbidden
	case "agent_unavailable":
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

// writeJSON encodes payload with the given status.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeError writes the structured error envelope. Body shape:
//
//	{"error":{"code":"...","message":"..."}}
//
// The hub-service-go Publisher only reads the response text on non-2xx and
// includes it in the LocalAgentError message, so the structured envelope is
// primarily for richer clients (Hub App diagnostics, future revisions).
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{
		"code":    code,
		"message": message,
	}})
}

// ptrInt returns a pointer to v. Used so ExpectedUID can distinguish "any uid
// acceptable" (nil) from "uid 0" (non-nil).
func ptrInt(v int) *int { return &v }
