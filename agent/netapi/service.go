// Package netapi serves the agent's Hub Network APIs: the member and network
// views (net/users, net/info) and member revocation (net/revoke).
//
// Agent-local port grants (net/ports/update) are retired
// (Docs/Devices/device-layer.md section 12): the agent enforces only
// hub-signed connection grants, so ports are reached through published
// shares. The path stays registered and refuses with errPortGrantsRetired so
// older apps get a clear answer.
package netapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/v57/channel-go/channelgo"
	protocol "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net/hubconn"
)

var errPortGrantsRetired = errors.New("port grants are retired; publish a share")

const (
	PortsUpdatePath = "net/ports/update"
	UsersPath       = "net/users"
	InfoPath        = "net/info"
	RevokePath      = "net/revoke"
)

type NetUser struct {
	ID       string    `json:"id"`
	IP       string    `json:"ip"`
	LastUsed time.Time `json:"lastUsed"`
	Online   bool      `json:"online"`
	// TCP and UDP are always empty: port grants are retired.
	TCP []uint16 `json:"tcp"`
	UDP []uint16 `json:"udp"`
}
type NetInfo struct {
	ID     string   `json:"id"`
	IP     string   `json:"ip"`
	IPv6   string   `json:"ipv6"`
	Online bool     `json:"online"`
	TCP    []uint16 `json:"tcp"`
	UDP    []uint16 `json:"udp"`
	VPN    bool     `json:"vpn"`
}
type PeerUsage struct {
	WireGuardKey string
	LastUsed     time.Time
	Online       bool
}

type Registry struct {
	mu       sync.RWMutex
	profiles map[string]protocol.AgentProfile
	revoked  map[string]struct{}
	path     string
}

func NewRegistry(path ...string) *Registry {
	r := &Registry{profiles: map[string]protocol.AgentProfile{}, revoked: map[string]struct{}{}}
	if len(path) > 0 {
		r.path = path[0]
		data, _ := os.ReadFile(r.path)
		var ids []string
		if json.Unmarshal(data, &ids) == nil {
			for _, id := range ids {
				r.revoked[id] = struct{}{}
			}
		}
	}
	return r
}
func (r *Registry) Replace(profiles []protocol.AgentProfile) {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := map[string]protocol.AgentProfile{}
	for _, p := range profiles {
		_, blocked := r.revoked[p.Key]
		if p.Key != "" && !blocked {
			next[p.Key] = p
		}
	}
	r.profiles = next
}
func (r *Registry) Exists(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.profiles[id]
	return ok
}

// Keys lists currently registered profile ids. Callers snapshot the set
// before Replace to detect newly learned users.
func (r *Registry) Keys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.profiles))
	for id := range r.profiles {
		keys = append(keys, id)
	}
	return keys
}

// Remove revokes one service key. The revocation list is persisted first; a
// failed durable write leaves the registry unchanged.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := make(map[string]struct{}, len(r.revoked)+1)
	for revoked := range r.revoked {
		next[revoked] = struct{}{}
	}
	next[id] = struct{}{}
	if err := r.saveLocked(next); err != nil {
		return fmt.Errorf("netapi: persist revocation: %w", err)
	}
	delete(r.profiles, id)
	r.revoked = next
	return nil
}
func (r *Registry) saveLocked(revoked map[string]struct{}) error {
	if r.path == "" {
		return nil
	}
	ids := make([]string, 0, len(revoked))
	for id := range revoked {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	data, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return atomicWriteFile(r.path, data, 0o600)
}
func (r *Registry) Profile(id string) (protocol.AgentProfile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[id]
	return p, ok
}
func (r *Registry) Addresses(id string) []string {
	p, ok := r.Profile(id)
	if !ok {
		return nil
	}
	return append([]string(nil), p.OverlayAddresses...)
}

type Options struct {
	Registry *Registry
	AgentID  func() string
	// Self reports whether a member key is this agent's own (its service key
	// or device:<id>). Default: equal to AgentID.
	Self           func(string) bool
	AgentAddresses func() (string, string)
	NodeOnline     func() bool
	VPN            func() bool
	PeerUsage      func() []PeerUsage
	// RevokePeer removes a member's WireGuard peer and its firewall state.
	RevokePeer func(protocol.AgentProfile) error
}

func Register(svc *hubconn.Service, options Options) error {
	if svc == nil || options.Registry == nil {
		return errors.New("netapi: incomplete options")
	}
	permission := func(name string) hubconn.Settings {
		return hubconn.Settings{Permissions: &hubconn.Permissions{Group: "Hub Network", Name: name}}
	}
	svc.Post(PortsUpdatePath, func(channelgo.Body) (any, error) {
		return nil, errPortGrantsRetired
	}, permission("Open and close ports"))
	svc.Stream(UsersPath, snapshotStream(func() any { return users(options) }), permission("View connected devices"))
	svc.Stream(InfoPath, snapshotStream(func() any {
		ipv4, ipv6 := options.AgentAddresses()
		return NetInfo{ID: options.AgentID(), IP: ipv4, IPv6: ipv6, Online: options.NodeOnline(), TCP: []uint16{}, UDP: []uint16{}, VPN: options.VPN()}
	}), permission("Read network"))
	svc.Post(RevokePath, func(body channelgo.Body) (any, error) {
		id, ok := body.Body.(string)
		if !ok || id == "" {
			return nil, errors.New("net/revoke requires a member key")
		}
		profile, ok := options.Registry.Profile(id)
		if !ok {
			return nil, errors.New("unknown user")
		}
		if options.RevokePeer != nil {
			if err := options.RevokePeer(profile); err != nil {
				return nil, err
			}
		}
		if err := options.Registry.Remove(id); err != nil {
			return nil, err
		}
		return nil, nil
	}, permission("Revoke access"))
	return nil
}

func users(o Options) []NetUser {
	usage := map[string]PeerUsage{}
	if o.PeerUsage != nil {
		for _, p := range o.PeerUsage() {
			usage[p.WireGuardKey] = p
		}
	}
	o.Registry.mu.RLock()
	defer o.Registry.mu.RUnlock()
	out := make([]NetUser, 0, len(o.Registry.profiles))
	self := o.Self
	if self == nil {
		self = func(id string) bool { return id == o.AgentID() }
	}
	for id, p := range o.Registry.profiles {
		if self(id) {
			continue
		}
		u := usage[p.WireGuardKey]
		ip := ""
		for _, address := range p.OverlayAddresses {
			if parsed := net.ParseIP(address); parsed != nil && parsed.To4() != nil {
				ip = address
				break
			}
		}
		lastUsed := u.LastUsed
		if lastUsed.IsZero() {
			// hub-pro reports when the member last connected.
			lastUsed, _ = time.Parse(time.RFC3339Nano, p.ConnectedAt)
		}
		out = append(out, NetUser{ID: id, IP: ip, LastUsed: lastUsed, Online: p.Online || u.Online, TCP: []uint16{}, UDP: []uint16{}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func snapshotStream(snapshot func() any) channelgo.StreamFunction {
	return func(_ channelgo.Body, emit channelgo.StreamEmitter) error {
		var previous string
		for !emit.IsCancelled() {
			value := snapshot()
			encoded, _ := json.Marshal(value)
			if string(encoded) != previous {
				if err := emit.Emit(value); err != nil {
					return err
				}
				previous = string(encoded)
			}
			time.Sleep(time.Second)
		}
		return nil
	}
}
func decode(value any, target any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, target)
}

// atomicWriteFile durably replaces path through a same-directory temp file,
// fsync, and rename so a crash mid-write never leaves a truncated revocation
// file behind.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
