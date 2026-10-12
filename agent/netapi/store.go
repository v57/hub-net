package netapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type UpdatePorts struct {
	Users  []string              `json:"users,omitempty"`
	Set    *[]UpdatePortsCommand `json:"set,omitempty"`
	Update *[]UpdatePortsCommand `json:"update,omitempty"`
}

type UpdatePortsCommand struct {
	Port uint16 `json:"port"`
	TCP  *bool  `json:"tcp,omitempty"`
	UDP  *bool  `json:"udp,omitempty"`
	Add  *bool  `json:"add,omitempty"`
}

type Ports struct{ TCP, UDP []uint16 }

type Store struct {
	mu      sync.RWMutex
	global  portSet
	users   map[string]portSet
	changed chan struct{}
	path    string
}

type portSet struct{ tcp, udp map[uint16]struct{} }
type Snapshot struct {
	global portSet
	users  map[string]portSet
}

func NewStore(path ...string) *Store {
	s := &Store{global: newPortSet(), users: map[string]portSet{}, changed: make(chan struct{})}
	if len(path) > 0 {
		s.path = path[0]
		s.load()
	}
	return s
}
func newPortSet() portSet { return portSet{tcp: map[uint16]struct{}{}, udp: map[uint16]struct{}{}} }

// atomicWriteFile durably replaces path through a same-directory temp file,
// fsync, and rename so a crash mid-write never leaves a truncated grants or
// revocation file behind.
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

func (s *Store) Apply(request UpdatePorts, userExists func(string) bool) error {
	if (request.Set == nil) == (request.Update == nil) {
		return errors.New("exactly one of set or update is required")
	}
	if request.Users != nil && len(request.Users) == 0 {
		return errors.New("users cannot be empty")
	}
	commands := request.Update
	replace := false
	if request.Set != nil {
		commands, replace = request.Set, true
	}
	if commands == nil {
		return errors.New("commands required")
	}
	for _, command := range *commands {
		if command.Port == 0 {
			return errors.New("port must be 1...65535")
		}
		tcp, udp := flag(command.TCP), flag(command.UDP)
		if !tcp && !udp {
			return errors.New("tcp and udp cannot both be false")
		}
	}
	if request.Users != nil {
		seen := map[string]struct{}{}
		for _, user := range request.Users {
			if user == "" || !userExists(user) {
				return errors.New("unknown user")
			}
			if _, ok := seen[user]; ok {
				continue
			}
			seen[user] = struct{}{}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	apply := func(target portSet) portSet {
		if replace {
			target = newPortSet()
		}
		for _, command := range *commands {
			add := replace || flag(command.Add)
			if flag(command.TCP) {
				mutate(target.tcp, command.Port, add)
			}
			if flag(command.UDP) {
				mutate(target.udp, command.Port, add)
			}
		}
		return target
	}
	nextGlobal := cloneSet(s.global)
	nextUsers := cloneUsers(s.users)
	if request.Users == nil {
		nextGlobal = apply(nextGlobal)
	} else {
		for _, user := range request.Users {
			target, ok := nextUsers[user]
			if !ok {
				target = newPortSet()
			}
			nextUsers[user] = apply(target)
		}
	}
	// Persist the next state before mutating memory: a failed durable write
	// leaves the in-memory grants unchanged so the caller can fail safely.
	if err := s.saveStateLocked(nextGlobal, nextUsers); err != nil {
		return fmt.Errorf("netapi: persist port update: %w", err)
	}
	s.global = nextGlobal
	s.users = nextUsers
	close(s.changed)
	s.changed = make(chan struct{})
	return nil
}

func (s *Store) Global() Ports { s.mu.RLock(); defer s.mu.RUnlock(); return snapshot(s.global) }
func (s *Store) User(id string) Ports {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return snapshot(s.users[id])
}
func (s *Store) Effective(id string) Ports {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return union(s.global, s.users[id])
}
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	nextUsers := cloneUsers(s.users)
	delete(nextUsers, id)
	if err := s.saveStateLocked(s.global, nextUsers); err != nil {
		return fmt.Errorf("netapi: persist revoke: %w", err)
	}
	s.users = nextUsers
	close(s.changed)
	s.changed = make(chan struct{})
	return nil
}
func (s *Store) Changed() <-chan struct{} { s.mu.RLock(); defer s.mu.RUnlock(); return s.changed }
func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Snapshot{global: cloneSet(s.global), users: cloneUsers(s.users)}
}
func (s *Store) Restore(value Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nextGlobal := cloneSet(value.global)
	nextUsers := cloneUsers(value.users)
	_ = s.saveStateLocked(nextGlobal, nextUsers)
	s.global = nextGlobal
	s.users = nextUsers
	close(s.changed)
	s.changed = make(chan struct{})
}

func flag(value *bool) bool { return value == nil || *value }
func mutate(set map[uint16]struct{}, port uint16, add bool) {
	if add {
		set[port] = struct{}{}
	} else {
		delete(set, port)
	}
}
func snapshot(set portSet) Ports { return Ports{TCP: sorted(set.tcp), UDP: sorted(set.udp)} }
func sorted(set map[uint16]struct{}) []uint16 {
	out := make([]uint16, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func union(a, b portSet) Ports {
	c := newPortSet()
	for p := range a.tcp {
		c.tcp[p] = struct{}{}
	}
	for p := range b.tcp {
		c.tcp[p] = struct{}{}
	}
	for p := range a.udp {
		c.udp[p] = struct{}{}
	}
	for p := range b.udp {
		c.udp[p] = struct{}{}
	}
	return snapshot(c)
}
func cloneSet(value portSet) portSet {
	out := newPortSet()
	for p := range value.tcp {
		out.tcp[p] = struct{}{}
	}
	for p := range value.udp {
		out.udp[p] = struct{}{}
	}
	return out
}
func cloneUsers(value map[string]portSet) map[string]portSet {
	out := map[string]portSet{}
	for id, ports := range value {
		out[id] = cloneSet(ports)
	}
	return out
}

type persistedPorts struct {
	Global Ports            `json:"global"`
	Users  map[string]Ports `json:"users"`
}

func (s *Store) load() {
	data, _ := os.ReadFile(s.path)
	var value persistedPorts
	if json.Unmarshal(data, &value) != nil {
		return
	}
	s.global = setFrom(value.Global)
	for id, ports := range value.Users {
		s.users[id] = setFrom(ports)
	}
}
func (s *Store) saveStateLocked(global portSet, users map[string]portSet) error {
	if s.path == "" {
		return nil
	}
	value := persistedPorts{Global: snapshot(global), Users: map[string]Ports{}}
	for id, ports := range users {
		value.Users[id] = snapshot(ports)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomicWriteFile(s.path, data, 0o600)
}
func setFrom(value Ports) portSet {
	out := newPortSet()
	for _, p := range value.TCP {
		if p > 0 {
			out.tcp[p] = struct{}{}
		}
	}
	for _, p := range value.UDP {
		if p > 0 {
			out.udp[p] = struct{}{}
		}
	}
	return out
}
