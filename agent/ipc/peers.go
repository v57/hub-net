// peers.go enforces the local-client invariant from PLATFORMS.md:
//
//	"IPC accepts local clients only. Socket directory ownership, socket mode,
//	peer credentials, nonce freshness, and service signatures are all checked;
//	local filesystem access alone is not a service identity proof."
//
// Peer credentials are read at connection-accept time on Linux (SO_PEERCRED)
// and Darwin (LOCAL_PEERCRED). The unixListener wrapper attaches the verified
// uid to each connection's context via http.Server.ConnContext so handlers can
// branch on it without re-issuing the syscall.
package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
)

// PeerPolicy controls local-client enforcement.
type PeerPolicy struct {
	// AllowAnyLocal disables peer-credential checks entirely. Use only when
	// the socket's filesystem permissions already restrict access to a trusted
	// group and the platform cannot supply peer credentials.
	AllowAnyLocal bool
	// ExpectedUID, when non-nil, requires the peer's effective uid to equal
	// this value. Nil means "do not constrain by uid" (still subject to
	// RootOK for root peers).
	ExpectedUID *int
	// RootOK permits uid 0 even when ExpectedUID points elsewhere. Root-owned
	// services (e.g. a system hub-launcher) may legitimately connect.
	RootOK bool
}

// peerCtxKey is the context key carrying the resolved peer uid.
type peerCtxKey struct{}

// ErrPeerUnknown is returned when peer credentials cannot be read on a
// platform that requires them.
var ErrPeerUnknown = errors.New("ipc: peer credentials unavailable")

// ErrPeerForbidden is returned when the peer uid is not authorized.
var ErrPeerForbidden = errors.New("ipc: peer uid not authorized")

// VerifyLocalPeer reports whether the request originated from a peer that
// satisfies policy. The peer uid is read from the request context, populated
// by the ConnContext hook installed in server.go.
func VerifyLocalPeer(r *http.Request, policy PeerPolicy) error {
	if policy.AllowAnyLocal {
		return nil
	}
	uid, ok := PeerUIDFromContext(r.Context())
	if !ok {
		// No uid was attached: either the connection never reached our
		// ConnContext (impossible with our listener) or the syscall failed.
		return ErrPeerUnknown
	}
	return authorizeUID(uid, policy)
}

// PeerUIDFromContext returns the peer uid attached by the ConnContext hook.
func PeerUIDFromContext(ctx context.Context) (int, bool) {
	uid, ok := ctx.Value(peerCtxKey{}).(int)
	return uid, ok
}

// authorizeUID applies the policy to a resolved peer uid.
func authorizeUID(uid int, policy PeerPolicy) error {
	if policy.RootOK && uid == 0 {
		return nil
	}
	if policy.ExpectedUID != nil && uid == *policy.ExpectedUID {
		return nil
	}
	return fmt.Errorf("%w: peer uid %d", ErrPeerForbidden, uid)
}

// withPeerUID stores the peer uid in the request context. Used by the
// ConnContext hook.
func withPeerUID(ctx context.Context, uid int) context.Context {
	return context.WithValue(ctx, peerCtxKey{}, uid)
}

// peerConnListener wraps a Unix-domain listener so each accepted connection
// is annotated with the peer's effective uid. The uid is read once at accept
// time on Linux (SO_PEERCRED) and Darwin (LOCAL_PEERCRED) and stored in a
// side table keyed by the *net.UnixConn so ConnContext can look it up.
type peerConnListener struct {
	net.Listener
	mu    sync.Mutex
	creds map[*net.UnixConn]int
}

func newPeerConnListener(ln net.Listener) *peerConnListener {
	return &peerConnListener{
		Listener: ln,
		creds:    make(map[*net.UnixConn]int),
	}
}

// Accept delegates to the underlying listener and records the peer uid.
func (l *peerConnListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		// Not a Unix socket (e.g. tests using a TCP listener): do not
		// annotate; VerifyLocalPeer will reject unless AllowAnyLocal is set.
		return conn, nil
	}
	uid, _ := readPeerUID(uc) // _ = unreadable is non-fatal; caller policy decides
	l.mu.Lock()
	l.creds[uc] = uid
	l.mu.Unlock()
	return conn, nil
}

// uidFor returns the recorded peer uid for conn, if any.
func (l *peerConnListener) uidFor(conn net.Conn) (int, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	uid, ok := l.creds[uc]
	return uid, ok
}

// forget drops the conn's recorded uid. Called when the conn closes.
func (l *peerConnListener) forget(conn net.Conn) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	l.mu.Lock()
	delete(l.creds, uc)
	l.mu.Unlock()
}

// readPeerUID reads the connecting peer's effective uid via the platform's
// peer-credential socket option.
func readPeerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid int
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		uid, sockErr = peerUIDFromFD(int(fd))
	})
	if ctrlErr != nil {
		return 0, ctrlErr
	}
	return uid, sockErr
}

// peerUIDFromFD is implemented per-platform in peers_linux.go,
// peers_darwin.go, peers_other.go.

// connContext is the http.Server.ConnContext hook that attaches the peer uid
// to each connection's base context. It is safe to call concurrently.
func (l *peerConnListener) connContext(ctx context.Context, conn net.Conn) context.Context {
	if uid, ok := l.uidFor(conn); ok {
		return withPeerUID(ctx, uid)
	}
	return ctx
}
