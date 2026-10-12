package netapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/v57/channel-go/channelgo"
	hubservice "github.com/v57/hub-service-go"
	"github.com/v57/hub-service-go/protocol"
	"github.com/v57/hub-service-go/service"
)

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
	TCP      []uint16  `json:"tcp"`
	UDP      []uint16  `json:"udp"`
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
	Store          *Store
	Registry       *Registry
	AgentID        func() string
	AgentAddresses func() (string, string)
	NodeOnline     func() bool
	VPN            func() bool
	PeerUsage      func() []PeerUsage
	ApplyFirewall  func(string, Ports) error
	RevokePeer     func(protocol.AgentProfile) error
}

func Register(svc *hubservice.Service, options Options) error {
	if svc == nil || options.Store == nil || options.Registry == nil {
		return errors.New("netapi: incomplete options")
	}
	permission := func(name string) service.Settings {
		return service.Settings{Permissions: &service.Permissions{Group: "Hub Network", Name: name}}
	}
	svc.Post(PortsUpdatePath, func(body channelgo.Body) (any, error) {
		var request UpdatePorts
		if err := decode(body.Body, &request); err != nil {
			return nil, err
		}
		targets := append([]string(nil), request.Users...)
		if request.Users == nil {
			options.Registry.mu.RLock()
			for id := range options.Registry.profiles {
				targets = append(targets, id)
			}
			options.Registry.mu.RUnlock()
		}
		previousState := options.Store.Snapshot()
		previousPorts := map[string]Ports{}
		for _, id := range targets {
			previousPorts[id] = options.Store.Effective(id)
		}
		if err := options.Store.Apply(request, options.Registry.Exists); err != nil {
			return nil, err
		}
		if options.ApplyFirewall != nil {
			for index, id := range targets {
				if err := options.ApplyFirewall(id, options.Store.Effective(id)); err != nil {
					options.Store.Restore(previousState)
					for _, rollbackID := range targets[:index] {
						_ = options.ApplyFirewall(rollbackID, previousPorts[rollbackID])
					}
					return nil, err
				}
			}
		}
		return nil, nil
	}, permission("Open and close ports"))
	svc.Stream(UsersPath, snapshotStream(func() any { return users(options) }), permission("View connected devices"))
	svc.Stream(InfoPath, snapshotStream(func() any {
		ipv4, ipv6 := options.AgentAddresses()
		ports := options.Store.Global()
		return NetInfo{ID: options.AgentID(), IP: ipv4, IPv6: ipv6, Online: options.NodeOnline(), TCP: ports.TCP, UDP: ports.UDP, VPN: options.VPN()}
	}), permission("Read network"))
	svc.Post(RevokePath, func(body channelgo.Body) (any, error) {
		id, ok := body.Body.(string)
		if !ok || id == "" {
			return nil, errors.New("net/revoke requires service key")
		}
		options.Registry.mu.RLock()
		profile, ok := options.Registry.profiles[id]
		options.Registry.mu.RUnlock()
		if !ok {
			return nil, errors.New("unknown user")
		}
		previousPorts := options.Store.Effective(id)
		if options.ApplyFirewall != nil {
			if err := options.ApplyFirewall(id, Ports{}); err != nil {
				return nil, err
			}
		}
		if options.RevokePeer != nil {
			if err := options.RevokePeer(profile); err != nil {
				if options.ApplyFirewall != nil {
					_ = options.ApplyFirewall(id, previousPorts)
				}
				return nil, err
			}
		}
		if err := options.Store.Revoke(id); err != nil {
			return nil, err
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
	for id, p := range o.Registry.profiles {
		if id == o.AgentID() {
			continue
		}
		u := usage[p.WireGuardKey]
		ports := o.Store.User(id)
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
		out = append(out, NetUser{ID: id, IP: ip, LastUsed: lastUsed, Online: p.Online || u.Online, TCP: ports.TCP, UDP: ports.UDP})
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
