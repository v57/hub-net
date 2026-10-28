package hubnet

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/v57/hub-net/membership"
	"github.com/v57/hub-net/publications"
	"github.com/v57/hub-net/supervisor"
	"github.com/v57/hub-net/translation"
)

// SessionOptions builds fully isolated Agent options for one joined Hub.
// Callers must return fresh adapters, DNS installers, enforcement backends,
// and connection checkers when those implementations contain mutable state.
type SessionOptions func(supervisor.Membership) (Options, error)

// Daemon is the multi-Hub process boundary. Agent remains the implementation
// of one isolated Hub session; Daemon owns their independent lifecycles.
type Daemon struct {
	supervisor  *supervisor.Supervisor
	translation *translation.Manager
}

type HubListItem struct {
	ID             string            `json:"id"`
	Alias          string            `json:"alias"`
	Header         string            `json:"header"`
	Status         supervisor.Status `json:"status"`
	VirtualIPv4    string            `json:"virtualIpv4,omitempty"`
	VirtualIPv6    string            `json:"virtualIpv6,omitempty"`
	NodeURL        string            `json:"nodeUrl"`
	Error          string            `json:"error,omitempty"`
	GatewayAllowed bool              `json:"gatewayAllowed"`
	// OverlayIPv4 and OverlayIPv6 are this device's addresses on the Hub's
	// network (canonical, before any translation).
	OverlayIPv4 string `json:"overlayIpv4,omitempty"`
	OverlayIPv6 string `json:"overlayIpv6,omitempty"`
}

func NewDaemon(options SessionOptions) (*Daemon, error) {
	return newDaemon(options, nil)
}

// NewDaemonWithTranslation couples every restored Hub session to one
// independently allocated translated address space.
func NewDaemonWithTranslation(options SessionOptions, manager *translation.Manager) (*Daemon, error) {
	if manager == nil {
		return nil, errors.New("hubnet: translation manager required")
	}
	return newDaemon(options, manager)
}

func newDaemon(options SessionOptions, manager *translation.Manager) (*Daemon, error) {
	if options == nil {
		return nil, errors.New("hubnet: session options factory required")
	}
	sessionSupervisor, err := supervisor.New(func(membership supervisor.Membership) (supervisor.Session, error) {
		sessionOptions, err := options(membership)
		if err != nil {
			return nil, err
		}
		if manager != nil {
			originalActivate := sessionOptions.ActivateNetwork
			sessionOptions.ActivateNetwork = func() error {
				if _, err := manager.Activate(
					membership.ID, membership.InterfaceName,
					membership.TranslatedIPv4, membership.TranslatedIPv6,
				); err != nil {
					return err
				}
				if originalActivate != nil {
					if err := originalActivate(); err != nil {
						_ = manager.Deactivate(membership.ID)
						return err
					}
				}
				return nil
			}
		}
		agent, err := New(sessionOptions)
		if err != nil {
			return nil, err
		}
		if manager == nil {
			return agent, nil
		}
		return translatedSession{Session: agent, membershipID: membership.ID, manager: manager}, nil
	})
	if err != nil {
		return nil, err
	}
	return &Daemon{supervisor: sessionSupervisor, translation: manager}, nil
}

// Run starts disconnected. Membership storage/control IPC adds sessions with
// Add; no singleton Hub connection is inferred from installation config.
func (d *Daemon) Run(ctx context.Context) error {
	err := d.supervisor.Run(ctx)
	if d.translation != nil {
		err = errors.Join(err, d.translation.DeactivateAll())
	}
	return err
}

func (d *Daemon) WaitRunning(ctx context.Context) error {
	return d.supervisor.WaitRunning(ctx)
}

func (d *Daemon) Add(membership supervisor.Membership) error {
	return d.supervisor.Add(membership)
}

func (d *Daemon) OpenShare(ctx context.Context, membershipID string, entry publications.Entry) error {
	return d.supervisor.OpenShare(ctx, membershipID, entry)
}

func (d *Daemon) CloseShare(ctx context.Context, membershipID, name string) error {
	return d.supervisor.CloseShare(ctx, membershipID, name)
}

func (d *Daemon) SetGateway(ctx context.Context, membershipID string, allowed bool) error {
	return d.supervisor.SetGateway(ctx, membershipID, allowed)
}

// Restore loads every healthy persisted membership independently. Corrupt
// records and sessions that fail construction become scoped diagnostics while
// healthy siblings still start.
func (d *Daemon) Restore(store *membership.Store) ([]membership.Diagnostic, error) {
	if store == nil {
		return nil, errors.New("hubnet: membership store required")
	}
	records, diagnostics, err := store.Load()
	if err != nil {
		return nil, err
	}
	for _, stored := range records {
		if stored.Record.Paused {
			continue
		}
		if d.translation != nil {
			if allocationErr := d.translation.CleanStale(
				stored.Record.InterfaceName,
				stored.Record.TranslatedIPv4, stored.Record.TranslatedIPv6,
			); allocationErr != nil {
				diagnostics = append(diagnostics, membership.Diagnostic{
					ID: stored.Record.ID, Error: allocationErr.Error(),
				})
				continue
			}
			allocation, allocationErr := d.translation.Reserve(
				stored.Record.ID,
				stored.Record.TranslatedIPv4, stored.Record.TranslatedIPv6,
			)
			if allocationErr != nil {
				diagnostics = append(diagnostics, membership.Diagnostic{
					ID: stored.Record.ID, Error: allocationErr.Error(),
				})
				continue
			}
			if stored.Record.TranslatedIPv4 == "" {
				stored, allocationErr = store.UpdateTranslation(
					stored.Record.ID, allocation.IPv4.String(), allocation.IPv6.String(),
				)
				if allocationErr != nil {
					_ = d.translation.Deactivate(stored.Record.ID)
					diagnostics = append(diagnostics, membership.Diagnostic{
						ID: stored.Record.ID, Error: allocationErr.Error(),
					})
					continue
				}
			}
		}
		var hubAddress any
		if len(stored.Record.HubAddress) > 0 {
			if err := json.Unmarshal(stored.Record.HubAddress, &hubAddress); err != nil {
				diagnostics = append(diagnostics, membership.Diagnostic{
					ID: stored.Record.ID, Error: "decode Hub address: " + err.Error(),
				})
				continue
			}
		}
		record := supervisor.Membership{
			ID:               stored.Record.ID,
			Alias:            stored.Record.Alias,
			Header:           stored.Record.Header,
			HubAddress:       hubAddress,
			NodeURL:          stored.Record.NodeURL,
			TranslatedIPv4:   stored.Record.TranslatedIPv4,
			TranslatedIPv6:   stored.Record.TranslatedIPv6,
			StateDir:         stored.StateDir,
			IdentityPath:     stored.IdentityPath,
			WireGuardKeyPath: stored.WireGuardKeyPath,
			PublicationsPath: stored.Record.PublicationsPath,
			InterfaceName:    stored.Record.InterfaceName,
			GatewayAllowed:   stored.Record.GatewayAllowed,
			Local:            stored.Record.Local,
			OverlayIPv4:      stored.Record.CanonicalIPv4,
			OverlayIPv6:      stored.Record.CanonicalIPv6,
		}
		if err := d.Add(record); err != nil {
			if d.translation != nil {
				_ = d.translation.Deactivate(stored.Record.ID)
			}
			diagnostics = append(diagnostics, membership.Diagnostic{
				ID: stored.Record.ID, Error: err.Error(),
			})
		}
	}
	return diagnostics, nil
}

type translatedSession struct {
	supervisor.Session
	membershipID string
	manager      *translation.Manager
}

// Connected forwards the wrapped session's Hub connection state.
func (s translatedSession) Connected() bool {
	reporter, ok := s.Session.(supervisor.ConnectionReporter)
	return !ok || reporter.Connected()
}

// OverlayAddress forwards the wrapped session's overlay address.
func (s translatedSession) OverlayAddress() string {
	if reporter, ok := s.Session.(supervisor.AddressReporter); ok {
		return reporter.OverlayAddress()
	}
	return ""
}

func (s translatedSession) Run(ctx context.Context) error {
	defer s.manager.Deactivate(s.membershipID)
	return s.Session.Run(ctx)
}

func (d *Daemon) Remove(membershipID string) error {
	if err := d.supervisor.Remove(membershipID); err != nil {
		return err
	}
	if d.translation != nil {
		return d.translation.Deactivate(membershipID)
	}
	return nil
}

func (d *Daemon) Sessions() []supervisor.Snapshot {
	return d.supervisor.Snapshots()
}

func (d *Daemon) LookupAlias(alias string) (supervisor.Snapshot, bool) {
	return d.supervisor.LookupAlias(alias)
}

func (d *Daemon) List() []HubListItem {
	snapshots := d.supervisor.Snapshots()
	items := make([]HubListItem, 0, len(snapshots))
	for _, snapshot := range snapshots {
		items = append(items, HubListItem{
			ID: snapshot.Membership.ID, Alias: snapshot.Membership.Alias,
			Header: snapshot.Membership.Header, Status: snapshot.Status,
			VirtualIPv4: snapshot.Membership.TranslatedIPv4,
			VirtualIPv6: snapshot.Membership.TranslatedIPv6,
			NodeURL:     snapshot.Membership.NodeURL, Error: snapshot.Error,
			GatewayAllowed: snapshot.Membership.GatewayAllowed,
			OverlayIPv4:    snapshot.OverlayIPv4,
			OverlayIPv6:    snapshot.Membership.OverlayIPv6,
		})
	}
	return items
}

// RefreshHeader persists latest remote display header and updates live list
// state. Stable alias remains unchanged.
func (d *Daemon) RefreshHeader(store *membership.Store, id, header string) error {
	if store == nil {
		return errors.New("hubnet: membership store required")
	}
	if _, err := store.UpdateHeader(id, header); err != nil {
		return err
	}
	d.supervisor.UpdateHeader(id, header)
	return nil
}

func (d *Daemon) Shutdown() {
	d.supervisor.Shutdown()
	if d.translation != nil {
		_ = d.translation.DeactivateAll()
	}
}
