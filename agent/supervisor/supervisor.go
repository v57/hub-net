// Package supervisor owns independent per-Hub agent sessions.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/v57/hub-net/publications"
)

// Membership is immutable session identity and isolation metadata loaded from
// persistent membership storage. Secret material is referenced by paths, never
// copied between sessions.
type Membership struct {
	ID               string
	Alias            string
	Header           string
	HubAddress       any
	NodeURL          string
	TranslatedIPv4   string
	TranslatedIPv6   string
	StateDir         string
	IdentityPath     string
	WireGuardKeyPath string
	PublicationsPath string
	InterfaceName    string
	GatewayAllowed   bool
	Local            bool
}

func (m Membership) validate() error {
	if m.ID == "" {
		return errors.New("supervisor: membership ID required")
	}
	if m.Alias == "" {
		return errors.New("supervisor: membership alias required")
	}
	if m.StateDir == "" || m.IdentityPath == "" || m.WireGuardKeyPath == "" {
		return errors.New("supervisor: per-Hub state and key paths required")
	}
	if m.InterfaceName == "" {
		return errors.New("supervisor: per-Hub interface name required")
	}
	return nil
}

// Session is one complete Hub runtime. Implementations own their Hub service,
// profile, WireGuard adapter, node pool, grants, DNS, enforcement, and
// publications. Run must stop after ctx cancellation. Shutdown must be safe to
// call more than once.
type Session interface {
	Run(context.Context) error
	Shutdown()
}

type ShareSession interface {
	OpenShare(context.Context, publications.Entry) error
	CloseShare(context.Context, string) error
}

type GatewaySession interface {
	EnableGateway(context.Context) error
	DisableGateway(context.Context) error
}

// Factory constructs a fresh Session for one membership. It must not cache or
// share mutable networking state across calls.
type Factory func(Membership) (Session, error)

type Status string

const (
	StatusStarting     Status = "starting"
	StatusConnected    Status = "connected"
	StatusDisconnected Status = "disconnected"
	StatusError        Status = "error"
	StatusStopping     Status = "stopping"
)

type Snapshot struct {
	Membership Membership
	Status     Status
	Error      string
	UpdatedAt  time.Time
}

type managedSession struct {
	membership Membership
	session    Session
	cancel     context.CancelFunc
	done       chan struct{}
	status     Status
	err        error
	updatedAt  time.Time
}

// Supervisor starts disconnected and dynamically owns zero or more isolated
// Hub sessions. Failure in one session is recorded and never cancels siblings.
type Supervisor struct {
	mu       sync.RWMutex
	factory  Factory
	sessions map[string]*managedSession
	aliases  map[string]string
	ctx      context.Context
	cancel   context.CancelFunc
	running  bool
	ready    chan struct{}
}

func New(factory Factory) (*Supervisor, error) {
	if factory == nil {
		return nil, errors.New("supervisor: session factory required")
	}
	return &Supervisor{
		factory:  factory,
		sessions: make(map[string]*managedSession),
		aliases:  make(map[string]string),
		ready:    make(chan struct{}),
	}, nil
}

// Run activates supervisor. It intentionally opens no Hub, node, or WireGuard
// connection until Add receives a persisted membership.
func (s *Supervisor) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("supervisor: already running")
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.running = true
	close(s.ready)
	runCtx := s.ctx
	s.mu.Unlock()

	<-runCtx.Done()
	s.stopAll()

	s.mu.Lock()
	s.running = false
	s.ctx = nil
	s.cancel = nil
	s.mu.Unlock()
	return runCtx.Err()
}

func (s *Supervisor) WaitRunning(ctx context.Context) error {
	select {
	case <-s.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Add starts one membership. Repeating same membership ID is idempotent.
func (s *Supervisor) Add(membership Membership) error {
	if err := membership.validate(); err != nil {
		return err
	}

	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return errors.New("supervisor: not running")
	}
	if existing, ok := s.sessions[membership.ID]; ok {
		if existing.membership == membership {
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		return fmt.Errorf("supervisor: membership %q already exists with different configuration", membership.ID)
	}
	if id, ok := s.aliases[membership.Alias]; ok {
		s.mu.Unlock()
		return fmt.Errorf("supervisor: alias %q already belongs to membership %q", membership.Alias, id)
	}
	session, err := s.factory(membership)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("supervisor: build session %q: %w", membership.ID, err)
	}
	sessionCtx, cancel := context.WithCancel(s.ctx)
	managed := &managedSession{
		membership: membership,
		session:    session,
		cancel:     cancel,
		done:       make(chan struct{}),
		status:     StatusStarting,
		updatedAt:  time.Now(),
	}
	s.sessions[membership.ID] = managed
	s.aliases[membership.Alias] = membership.ID
	s.mu.Unlock()

	go s.runSession(sessionCtx, membership.ID, managed)
	return nil
}

func (s *Supervisor) runSession(ctx context.Context, id string, managed *managedSession) {
	s.setResult(id, managed, StatusConnected, nil)
	err := managed.session.Run(ctx)
	status := StatusDisconnected
	if err != nil && !errors.Is(err, context.Canceled) {
		status = StatusError
	}
	s.setResult(id, managed, status, err)
	close(managed.done)
}

func (s *Supervisor) setResult(id string, managed *managedSession, status Status, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[id] != managed {
		return
	}
	managed.status = status
	managed.err = err
	managed.updatedAt = time.Now()
}

// Remove stops one session without affecting any sibling.
func (s *Supervisor) Remove(id string) error {
	s.mu.Lock()
	managed, ok := s.sessions[id]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	managed.status = StatusStopping
	managed.updatedAt = time.Now()
	delete(s.sessions, id)
	delete(s.aliases, managed.membership.Alias)
	s.mu.Unlock()

	managed.cancel()
	managed.session.Shutdown()
	<-managed.done
	return nil
}

func (s *Supervisor) stopAll() {
	s.mu.RLock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	s.mu.RUnlock()
	for _, id := range ids {
		_ = s.Remove(id)
	}
}

func (s *Supervisor) Shutdown() {
	s.mu.RLock()
	cancel := s.cancel
	s.mu.RUnlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Supervisor) Snapshots() []Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Snapshot, 0, len(s.sessions))
	for _, managed := range s.sessions {
		snapshot := Snapshot{
			Membership: managed.membership,
			Status:     managed.status,
			UpdatedAt:  managed.updatedAt,
		}
		if managed.err != nil {
			snapshot.Error = managed.err.Error()
		}
		result = append(result, snapshot)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Membership.Alias < result[j].Membership.Alias
	})
	return result
}

// LookupAlias resolves exact aliases only.
func (s *Supervisor) LookupAlias(alias string) (Snapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.aliases[alias]
	if !ok {
		return Snapshot{}, false
	}
	managed := s.sessions[id]
	result := Snapshot{Membership: managed.membership, Status: managed.status, UpdatedAt: managed.updatedAt}
	if managed.err != nil {
		result.Error = managed.err.Error()
	}
	return result, true
}

// UpdateHeader refreshes display metadata without changing stable alias.
func (s *Supervisor) UpdateHeader(id, header string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	managed, ok := s.sessions[id]
	if !ok {
		return false
	}
	managed.membership.Header = header
	managed.updatedAt = time.Now()
	return true
}

func (s *Supervisor) OpenShare(ctx context.Context, id string, entry publications.Entry) error {
	s.mu.RLock()
	managed, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("supervisor: membership %q not found", id)
	}
	session, ok := managed.session.(ShareSession)
	if !ok {
		return errors.New("supervisor: session does not support publications")
	}
	return session.OpenShare(ctx, entry)
}

func (s *Supervisor) CloseShare(ctx context.Context, id, name string) error {
	s.mu.RLock()
	managed, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("supervisor: membership %q not found", id)
	}
	session, ok := managed.session.(ShareSession)
	if !ok {
		return errors.New("supervisor: session does not support publications")
	}
	return session.CloseShare(ctx, name)
}

func (s *Supervisor) SetGateway(ctx context.Context, id string, allowed bool) error {
	s.mu.RLock()
	managed, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("supervisor: membership %q not found", id)
	}
	session, ok := managed.session.(GatewaySession)
	if !ok {
		return errors.New("supervisor: session does not support gateway serving")
	}
	var err error
	if allowed {
		err = session.EnableGateway(ctx)
	} else {
		err = session.DisableGateway(ctx)
	}
	if err == nil {
		s.mu.Lock()
		managed.membership.GatewayAllowed = allowed
		managed.updatedAt = time.Now()
		s.mu.Unlock()
	}
	return err
}
