package invitation

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// BootstrapPeer is node-mediated direct peer state. Close must remove all
// temporary candidate/session state and is safe after partial setup.
type BootstrapPeer interface {
	Close(context.Context) error
}

type Rendezvous interface {
	Open(context.Context, Decoded, JoinIdentity) (BootstrapPeer, error)
}

// Tunnel installs only the signed inviting-agent and hub-pro bootstrap routes.
type Tunnel interface {
	Up(context.Context, Decoded, BootstrapPeer, JoinIdentity) error
	Down(context.Context) error
}

type Hub interface {
	Claim(context.Context, Decoded, string) error
	Enroll(context.Context, Decoded, string, JoinIdentity) (Enrollment, error)
	Header(context.Context, Enrollment) (HubHeader, error)
	Release(context.Context, Decoded, string) error
}

type Store interface {
	// Stage atomically creates or resumes a private transaction directory.
	// Existing transaction identity wins, so a retry cannot rotate keys after
	// remote enrollment.
	Stage(context.Context, string, JoinIdentity) (JoinIdentity, error)
	// RecordEnrollment durably records remote commit before any later local
	// work. Repeating it with the same enrollment must be idempotent.
	RecordEnrollment(context.Context, string, Enrollment) error
	Commit(context.Context, string, Enrollment, HubHeader) (Membership, error)
	Rollback(context.Context, string) error
}

type JoinIdentity struct {
	ProfileKey   string
	AgentKey     string
	WireGuardKey string
}

type Enrollment struct {
	MembershipID string
	NetworkID    string
	Addresses    []string
}

type HubHeader struct {
	Name string
}

type Membership struct {
	ID    string
	Alias string
}

type Joiner struct {
	Node   Rendezvous
	Tunnel Tunnel
	Hub    Hub
	Store  Store
	Now    func() time.Time
	// Timeout bounds direct rendezvous and enrollment. Zero uses two minutes.
	Timeout time.Duration
}

const (
	defaultJoinTimeout    = 2 * time.Minute
	defaultCleanupTimeout = 5 * time.Second
)

// Join executes one staged transaction. Local validation happens before any
// collaborator call. Every pre-commit failure tears down staged state, tunnel,
// node session, and releases a remote claim when one exists.
func (j Joiner) Join(ctx context.Context, input, transactionID string, identity JoinIdentity) (membership Membership, err error) {
	if transactionID == "" {
		return Membership{}, errors.New("join: transaction ID required")
	}
	now := time.Now()
	if j.Now != nil {
		now = j.Now()
	}
	decoded, err := Decode(input, now)
	if err != nil {
		return Membership{}, err
	}
	if j.Node == nil || j.Tunnel == nil || j.Hub == nil || j.Store == nil {
		return Membership{}, errors.New("join: incomplete dependencies")
	}
	timeout := j.Timeout
	if timeout <= 0 {
		timeout = defaultJoinTimeout
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, decoded.Envelope.ExpiresAt)
	if remaining := expiresAt.Sub(now); remaining < timeout {
		timeout = remaining
	}
	joinCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ctx = joinCtx
	identity, err = j.Store.Stage(ctx, transactionID, identity)
	if err != nil {
		return Membership{}, fmt.Errorf("join: stage identity: %w", err)
	}
	staged := true
	var peer BootstrapPeer
	tunnelUp := false
	claimed := false
	enrolled := false
	defer func() {
		if err == nil {
			return
		}
		cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), defaultCleanupTimeout)
		defer cancelCleanup()
		var cleanupErrors []error
		if claimed && !enrolled {
			cleanupErrors = append(cleanupErrors, j.Hub.Release(cleanup, decoded, transactionID))
		}
		if tunnelUp {
			cleanupErrors = append(cleanupErrors, j.Tunnel.Down(cleanup))
		}
		if peer != nil {
			cleanupErrors = append(cleanupErrors, peer.Close(cleanup))
		}
		// Once enrollment commits remotely, preserve staged identity and
		// transaction ID. Retry reaches the idempotent enrollment result and
		// finishes one local membership instead of creating another.
		if staged && !enrolled {
			cleanupErrors = append(cleanupErrors, j.Store.Rollback(cleanup, transactionID))
		}
		err = errors.Join(err, errors.Join(cleanupErrors...))
	}()

	peer, err = j.Node.Open(ctx, decoded, identity)
	if err != nil {
		return Membership{}, fmt.Errorf("join: rendezvous: %w", err)
	}
	if err = j.Tunnel.Up(ctx, decoded, peer, identity); err != nil {
		return Membership{}, fmt.Errorf("join: bootstrap tunnel: %w", err)
	}
	tunnelUp = true
	if err = j.Hub.Claim(ctx, decoded, transactionID); err != nil {
		return Membership{}, fmt.Errorf("join: claim invitation: %w", err)
	}
	claimed = true
	enrollment, err := j.Hub.Enroll(ctx, decoded, transactionID, identity)
	if err != nil {
		return Membership{}, fmt.Errorf("join: enroll profile: %w", err)
	}
	enrolled = true
	claimed = false
	if err = j.Store.RecordEnrollment(ctx, transactionID, enrollment); err != nil {
		return Membership{}, fmt.Errorf("join: record enrollment: %w", err)
	}
	header, err := j.Hub.Header(ctx, enrollment)
	if err != nil {
		return Membership{}, fmt.Errorf("join: read hub header: %w", err)
	}
	membership, err = j.Store.Commit(ctx, transactionID, enrollment, header)
	if err != nil {
		return Membership{}, fmt.Errorf("join: commit membership: %w", err)
	}
	staged = false
	tunnelUp = false
	if err = j.Tunnel.Down(ctx); err != nil {
		return Membership{}, fmt.Errorf("join: replace bootstrap tunnel: %w", err)
	}
	closingPeer := peer
	peer = nil
	if err = closingPeer.Close(ctx); err != nil {
		return Membership{}, fmt.Errorf("join: close rendezvous: %w", err)
	}
	return membership, nil
}
