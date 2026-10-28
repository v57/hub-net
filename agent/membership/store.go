// Package membership persists multi-Hub session records and migrates the
// released singleton layout without rotating its private keys.
package membership

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const Version = 1

type Record struct {
	Version          int             `json:"version"`
	ID               string          `json:"id"`
	Alias            string          `json:"alias"`
	Header           string          `json:"header"`
	HubAddress       json.RawMessage `json:"hubAddress"`
	NetworkID        string          `json:"networkId"`
	NodeURL          string          `json:"nodeUrl"`
	InterfaceName    string          `json:"interfaceName"`
	CanonicalIPv4    string          `json:"canonicalIpv4,omitempty"`
	CanonicalIPv6    string          `json:"canonicalIpv6,omitempty"`
	TranslatedIPv4   string          `json:"translatedIpv4,omitempty"`
	TranslatedIPv6   string          `json:"translatedIpv6,omitempty"`
	GatewayAllowed   bool            `json:"gatewayAllowed"`
	PublicationsPath string          `json:"publicationsPath,omitempty"`
	// Local marks the hub that runs on this machine: its session binds as the
	// machine-local agent. Joined hubs bind with the join kind.
	Local bool `json:"local,omitempty"`
	// Paused keeps the membership with its keys and address but no session:
	// no interface, routes or Hub connection until it is resumed.
	Paused bool `json:"paused,omitempty"`
}

type Stored struct {
	Record           Record
	StateDir         string
	IdentityPath     string
	WireGuardKeyPath string
}

type Diagnostic struct {
	ID    string
	Error string
}

type index struct {
	Version  int      `json:"version"`
	IDs      []string `json:"ids"`
	Removing []string `json:"removing,omitempty"`
}

type stage struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Record  Record `json:"record"`
}

type Store struct {
	mu   sync.Mutex
	root string
}

func Open(root string) (*Store, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("membership: root must be absolute")
	}
	for _, path := range []string{root, filepath.Join(root, "memberships"), filepath.Join(root, "staged")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("membership: create state: %w", err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return nil, fmt.Errorf("membership: protect state: %w", err)
		}
	}
	return &Store{root: root}, nil
}

func (s *Store) Stage(record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validate(record); err != nil {
		return err
	}
	record.Version = Version
	return atomicJSON(s.stagePath(record.ID), stage{Version: Version, ID: record.ID, Record: record}, 0o600)
}

// Commit installs a complete staged record before atomically publishing its ID
// in the index. Repeating Commit after interruption is idempotent.
func (s *Store) Commit(id string) (Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pending stage
	if err := readJSON(s.stagePath(id), &pending); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			loaded, loadErr := s.loadOne(id)
			return loaded, loadErr
		}
		return Stored{}, fmt.Errorf("membership: read stage: %w", err)
	}
	if pending.Version != Version || pending.ID != id {
		return Stored{}, errors.New("membership: corrupt staged record")
	}
	if err := s.writeRecord(pending.Record); err != nil {
		return Stored{}, err
	}
	current, err := s.readIndex()
	if err != nil {
		return Stored{}, err
	}
	if !contains(current.IDs, id) {
		current.IDs = append(current.IDs, id)
		sort.Strings(current.IDs)
		if err := atomicJSON(s.indexPath(), current, 0o600); err != nil {
			return Stored{}, fmt.Errorf("membership: publish index: %w", err)
		}
	}
	if err := os.Remove(s.stagePath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Stored{}, fmt.Errorf("membership: remove stage: %w", err)
	}
	return s.loadOne(id)
}

// Recover finishes records whose directory was written before an interrupted
// index update. Invalid stages are reported and isolated.
func (s *Store) Recover() []Diagnostic {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(filepath.Join(s.root, "staged"))
	if err != nil {
		return []Diagnostic{{Error: err.Error()}}
	}
	var diagnostics []Diagnostic
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var pending stage
		path := filepath.Join(s.root, "staged", entry.Name())
		if err := readJSON(path, &pending); err != nil || pending.Version != Version || validate(pending.Record) != nil {
			diagnostics = append(diagnostics, Diagnostic{ID: pending.ID, Error: "corrupt staged membership: " + errorText(err)})
			continue
		}
		if _, err := os.Stat(s.recordPath(pending.ID)); err == nil {
			current, indexErr := s.readIndex()
			if indexErr == nil && !contains(current.IDs, pending.ID) {
				current.IDs = append(current.IDs, pending.ID)
				sort.Strings(current.IDs)
				indexErr = atomicJSON(s.indexPath(), current, 0o600)
			}
			if indexErr == nil {
				_ = os.Remove(path)
				continue
			}
			err = indexErr
		}
		diagnostics = append(diagnostics, Diagnostic{ID: pending.ID, Error: "incomplete staged membership: " + errorText(err)})
	}
	return diagnostics
}

// Load returns every valid indexed membership. A corrupt record becomes one
// scoped diagnostic and never prevents healthy siblings from starting.
func (s *Store) Load() ([]Stored, []Diagnostic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.readIndex()
	if err != nil {
		return nil, nil, err
	}
	var diagnostics []Diagnostic
	if len(current.Removing) > 0 {
		remaining := current.Removing[:0]
		for _, id := range current.Removing {
			if cleanupErr := s.removeFiles(id); cleanupErr != nil {
				remaining = append(remaining, id)
				diagnostics = append(diagnostics, Diagnostic{ID: id, Error: cleanupErr.Error()})
			}
		}
		current.Removing = remaining
		if err := atomicJSON(s.indexPath(), current, 0o600); err != nil {
			return nil, diagnostics, fmt.Errorf("membership: finish interrupted removal: %w", err)
		}
	}
	var records []Stored
	for _, id := range current.IDs {
		record, err := s.loadOne(id)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{ID: id, Error: err.Error()})
			continue
		}
		records = append(records, record)
	}
	return records, diagnostics, nil
}

// FindAlias resolves one exact local alias. No prefix or case-folded lookup is
// accepted by management commands.
func (s *Store) FindAlias(alias string) (Stored, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.readIndex()
	if err != nil {
		return Stored{}, false, err
	}
	for _, id := range current.IDs {
		stored, loadErr := s.loadOne(id)
		if loadErr != nil {
			continue
		}
		if stored.Record.Alias == alias {
			return stored, true, nil
		}
	}
	return Stored{}, false, nil
}

// Remove atomically makes a membership unavailable before deleting its
// private directory. Repeating removal is safe.
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.readIndex()
	if err != nil {
		return err
	}
	filtered := current.IDs[:0]
	found := false
	for _, candidate := range current.IDs {
		if candidate == id {
			found = true
			continue
		}
		filtered = append(filtered, candidate)
	}
	if found {
		current.IDs = filtered
		if !contains(current.Removing, id) {
			current.Removing = append(current.Removing, id)
			sort.Strings(current.Removing)
		}
		if err := atomicJSON(s.indexPath(), current, 0o600); err != nil {
			return fmt.Errorf("membership: mark removing: %w", err)
		}
	}
	if !found && !contains(current.Removing, id) {
		return nil
	}
	if err := s.removeFiles(id); err != nil {
		return err
	}
	current.Removing = removeValue(current.Removing, id)
	return atomicJSON(s.indexPath(), current, 0o600)
}

// RemoveAll removes every indexed membership independently.
func (s *Store) RemoveAll() error {
	s.mu.Lock()
	current, err := s.readIndex()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	for _, id := range current.IDs {
		if err := s.Remove(id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) removeFiles(id string) error {
	if err := os.Remove(s.stagePath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("membership: remove stage: %w", err)
	}
	if err := os.RemoveAll(s.memberDir(id)); err != nil {
		return fmt.Errorf("membership: remove private state: %w", err)
	}
	return nil
}

// UpdateHeader atomically refreshes remote display metadata while preserving
// immutable local alias and all session isolation fields.
func (s *Store) UpdateHeader(id, header string) (Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.loadOne(id)
	if err != nil {
		return Stored{}, err
	}
	stored.Record.Header = header
	if err := s.writeRecord(stored.Record); err != nil {
		return Stored{}, fmt.Errorf("membership: update header: %w", err)
	}
	return s.loadOne(id)
}

// UpdateGateway atomically persists explicit gateway-serving intent.
func (s *Store) UpdateGateway(id string, allowed bool) (Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.loadOne(id)
	if err != nil {
		return Stored{}, err
	}
	stored.Record.GatewayAllowed = allowed
	if err := s.writeRecord(stored.Record); err != nil {
		return Stored{}, fmt.Errorf("membership: update gateway: %w", err)
	}
	return s.loadOne(id)
}

// UpdatePaused persists whether the membership's session is paused.
func (s *Store) UpdatePaused(id string, paused bool) (Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.loadOne(id)
	if err != nil {
		return Stored{}, err
	}
	stored.Record.Paused = paused
	if err := s.writeRecord(stored.Record); err != nil {
		return Stored{}, fmt.Errorf("membership: update paused: %w", err)
	}
	return s.loadOne(id)
}

// UpdateCanonical persists the overlay addresses the Hub registered the
// membership with at its latest hub/net/bind. They can differ from the ones
// its join recorded: a device that was on the Hub before keeps its earlier
// addresses there. Empty values leave the recorded ones; an unchanged record
// is not rewritten.
func (s *Store) UpdateCanonical(id, ipv4, ipv6 string) (Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.loadOne(id)
	if err != nil {
		return Stored{}, err
	}
	changed := false
	if ipv4 != "" && ipv4 != stored.Record.CanonicalIPv4 {
		stored.Record.CanonicalIPv4 = ipv4
		changed = true
	}
	if ipv6 != "" && ipv6 != stored.Record.CanonicalIPv6 {
		stored.Record.CanonicalIPv6 = ipv6
		changed = true
	}
	if !changed {
		return stored, nil
	}
	if err := s.writeRecord(stored.Record); err != nil {
		return Stored{}, fmt.Errorf("membership: update address: %w", err)
	}
	return s.loadOne(id)
}

// UpdateTranslation atomically persists a complete allocation. Existing
// allocations are immutable so restart cannot silently change local hosts.
func (s *Store) UpdateTranslation(id, ipv4, ipv6 string) (Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.loadOne(id)
	if err != nil {
		return Stored{}, err
	}
	if stored.Record.TranslatedIPv4 != "" || stored.Record.TranslatedIPv6 != "" {
		if stored.Record.TranslatedIPv4 == ipv4 && stored.Record.TranslatedIPv6 == ipv6 {
			return stored, nil
		}
		return Stored{}, errors.New("membership: translated allocation is immutable")
	}
	if ipv4 == "" || ipv6 == "" {
		return Stored{}, errors.New("membership: complete translated allocation required")
	}
	stored.Record.TranslatedIPv4 = ipv4
	stored.Record.TranslatedIPv6 = ipv6
	if err := s.writeRecord(stored.Record); err != nil {
		return Stored{}, fmt.Errorf("membership: update translation: %w", err)
	}
	return s.loadOne(id)
}

// Legacy describes released singleton files. Migration copies, never moves,
// old material and writes marker only after new membership is durable.
type Legacy struct {
	ID               string
	Alias            string
	Header           string
	HubAddress       json.RawMessage
	NetworkID        string
	NodeURL          string
	InterfaceName    string
	IdentityPath     string
	WireGuardKeyPath string
	PublicationsPath string
}

func (s *Store) MigrateSingleton(legacy Legacy) (Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	marker := filepath.Join(s.root, "singleton-migrated.json")
	if _, err := os.Stat(marker); err == nil {
		return s.loadOne(legacy.ID)
	}
	record := Record{Version: Version, ID: legacy.ID, Alias: legacy.Alias, Header: legacy.Header,
		HubAddress: legacy.HubAddress, NetworkID: legacy.NetworkID, NodeURL: legacy.NodeURL,
		InterfaceName: legacy.InterfaceName, GatewayAllowed: false}
	if err := validate(record); err != nil {
		return Stored{}, err
	}
	dir := s.memberDir(record.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Stored{}, err
	}
	if err := copyPrivate(legacy.IdentityPath, filepath.Join(dir, "profile.identity")); err != nil {
		return Stored{}, fmt.Errorf("membership: migrate identity: %w", err)
	}
	if err := copyPrivate(legacy.WireGuardKeyPath, filepath.Join(dir, "wireguard.key")); err != nil {
		return Stored{}, fmt.Errorf("membership: migrate WireGuard key: %w", err)
	}
	if legacy.PublicationsPath != "" {
		target := filepath.Join(dir, "publications.json")
		if err := copyPrivate(legacy.PublicationsPath, target); err != nil {
			return Stored{}, fmt.Errorf("membership: migrate publications: %w", err)
		}
		record.PublicationsPath = target
	}
	if err := s.writeRecord(record); err != nil {
		return Stored{}, err
	}
	current, err := s.readIndex()
	if err != nil {
		return Stored{}, err
	}
	if !contains(current.IDs, record.ID) {
		current.IDs = append(current.IDs, record.ID)
		sort.Strings(current.IDs)
		if err := atomicJSON(s.indexPath(), current, 0o600); err != nil {
			return Stored{}, err
		}
	}
	if err := atomicJSON(marker, map[string]any{"version": Version, "membershipId": record.ID}, 0o600); err != nil {
		return Stored{}, err
	}
	return s.loadOne(record.ID)
}

func validate(record Record) error {
	if record.ID == "" || record.Alias == "" || record.InterfaceName == "" {
		return errors.New("membership: ID, alias, and interface name required")
	}
	if strings.ContainsAny(record.ID, `/\`) || record.ID == "." || record.ID == ".." {
		return errors.New("membership: invalid ID")
	}
	return nil
}

func (s *Store) writeRecord(record Record) error {
	record.Version = Version
	if err := os.MkdirAll(s.memberDir(record.ID), 0o700); err != nil {
		return err
	}
	return atomicJSON(s.recordPath(record.ID), record, 0o600)
}

func (s *Store) loadOne(id string) (Stored, error) {
	var record Record
	if err := readJSON(s.recordPath(id), &record); err != nil {
		return Stored{}, fmt.Errorf("membership %q: %w", id, err)
	}
	if record.Version != Version || record.ID != id {
		return Stored{}, fmt.Errorf("membership %q: corrupt or unsupported record", id)
	}
	if err := validate(record); err != nil {
		return Stored{}, fmt.Errorf("membership %q: %w", id, err)
	}
	dir := s.memberDir(id)
	return Stored{Record: record, StateDir: dir, IdentityPath: filepath.Join(dir, "profile.identity"),
		WireGuardKeyPath: filepath.Join(dir, "wireguard.key")}, nil
}

func (s *Store) readIndex() (index, error) {
	current := index{Version: Version}
	if err := readJSON(s.indexPath(), &current); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return current, nil
		}
		return index{}, fmt.Errorf("membership: read index: %w", err)
	}
	if current.Version != Version {
		return index{}, errors.New("membership: unsupported index version")
	}
	return current, nil
}

func (s *Store) indexPath() string { return filepath.Join(s.root, "memberships.json") }
func (s *Store) memberDir(id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(s.root, "memberships", hex.EncodeToString(sum[:]))
}

// MemberDir returns the private directory for one membership id. Callers that
// place per-membership material before Commit (for example a joined
// membership's identity and WireGuard key files) use it to target the same
// directory loadOne will derive.
func (s *Store) MemberDir(id string) string  { return s.memberDir(id) }
func (s *Store) recordPath(id string) string { return filepath.Join(s.memberDir(id), "record.json") }
func (s *Store) stagePath(id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(s.root, "staged", hex.EncodeToString(sum[:])+".json")
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func removeValue(values []string, value string) []string {
	result := values[:0]
	for _, candidate := range values {
		if candidate != value {
			result = append(result, candidate)
		}
	}
	return result
}

func readJSON(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}

func atomicJSON(path string, value any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func copyPrivate(source, target string) error {
	if source == "" {
		return errors.New("source path required")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	output, err := os.OpenFile(target+".migrating", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = io.Copy(output, input); err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(target + ".migrating")
		return err
	}
	if err := os.Rename(target+".migrating", target); err != nil {
		return err
	}
	return nil
}

func errorText(err error) string {
	if err == nil {
		return "invalid record"
	}
	return err.Error()
}
