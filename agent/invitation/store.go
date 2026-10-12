package invitation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/v57/hub-net/hubalias"
)

const membershipStoreVersion = 1

// JoinIdentity is the fresh service + WireGuard key pair staged before any
// remote work so a retried join cannot rotate keys after remote enrollment.
type JoinIdentity struct {
	Key          string
	WireGuardKey string
}

// Enrollment is the remote membership result recorded durably before any
// local commit work begins.
type Enrollment struct {
	MembershipID string
	NetworkID    string
	Addresses    []string
}

// HubHeader is the display header used to derive the membership alias.
type HubHeader struct {
	Name string `json:"name"`
}

// Membership is one committed local membership.
type Membership struct {
	ID    string
	Alias string
}

type stagedJoin struct {
	Version       int          `json:"version"`
	TransactionID string       `json:"transactionId"`
	Identity      JoinIdentity `json:"identity"`
	Enrollment    *Enrollment  `json:"enrollment,omitempty"`
}

type membershipIndex struct {
	Version     int                `json:"version"`
	Memberships []storedMembership `json:"memberships"`
}

type storedMembership struct {
	Membership Membership `json:"membership"`
	Enrollment Enrollment `json:"enrollment"`
	Header     HubHeader  `json:"header"`
}

// FileStore persists recoverable invitation transactions beneath one private
// state root. Atomic rename makes each stage and index update all-or-nothing.
type FileStore struct {
	mu   sync.Mutex
	root string
}

func NewFileStore(root string) (*FileStore, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("invitation store: root must be absolute")
	}
	if err := os.MkdirAll(filepath.Join(root, "staged"), 0o700); err != nil {
		return nil, fmt.Errorf("invitation store: create root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("invitation store: protect root: %w", err)
	}
	return &FileStore{root: root}, nil
}

func (s *FileStore) Stage(_ context.Context, transactionID string, identity JoinIdentity) (JoinIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if transactionID == "" {
		return JoinIdentity{}, errors.New("invitation store: transaction ID required")
	}
	path := s.stagePath(transactionID)
	var existing stagedJoin
	if err := readJSON(path, &existing); err == nil {
		if existing.Version != membershipStoreVersion || existing.TransactionID != transactionID {
			return JoinIdentity{}, errors.New("invitation store: corrupt staged transaction")
		}
		return existing.Identity, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return JoinIdentity{}, fmt.Errorf("invitation store: read stage: %w", err)
	}
	stage := stagedJoin{
		Version: membershipStoreVersion, TransactionID: transactionID, Identity: identity,
	}
	if err := atomicWriteJSON(path, stage, 0o600); err != nil {
		return JoinIdentity{}, fmt.Errorf("invitation store: write stage: %w", err)
	}
	return identity, nil
}

func (s *FileStore) RecordEnrollment(_ context.Context, transactionID string, enrollment Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stage, path, err := s.loadStage(transactionID)
	if err != nil {
		return err
	}
	if stage.Enrollment != nil && !reflect.DeepEqual(*stage.Enrollment, enrollment) {
		return errors.New("invitation store: enrollment changed for transaction")
	}
	stage.Enrollment = &enrollment
	return atomicWriteJSON(path, stage, 0o600)
}

func (s *FileStore) Commit(_ context.Context, transactionID string, enrollment Enrollment, header HubHeader) (Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stage, stagePath, err := s.loadStage(transactionID)
	if err != nil {
		return Membership{}, err
	}
	if stage.Enrollment == nil || !reflect.DeepEqual(*stage.Enrollment, enrollment) {
		return Membership{}, errors.New("invitation store: enrollment not durably recorded")
	}
	index, err := s.loadIndex()
	if err != nil {
		return Membership{}, err
	}
	for _, record := range index.Memberships {
		if record.Enrollment.MembershipID == enrollment.MembershipID {
			_ = os.Remove(stagePath)
			return record.Membership, nil
		}
	}
	membership := Membership{
		ID:    enrollment.MembershipID,
		Alias: nextAlias(header.Name, index.Memberships),
	}
	index.Memberships = append(index.Memberships, storedMembership{
		Membership: membership, Enrollment: enrollment, Header: header,
	})
	if err := atomicWriteJSON(filepath.Join(s.root, "memberships.json"), index, 0o600); err != nil {
		return Membership{}, fmt.Errorf("invitation store: commit index: %w", err)
	}
	if err := os.Remove(stagePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Membership{}, fmt.Errorf("invitation store: remove stage: %w", err)
	}
	return membership, nil
}

func (s *FileStore) Rollback(_ context.Context, transactionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.stagePath(transactionID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *FileStore) loadStage(transactionID string) (stagedJoin, string, error) {
	path := s.stagePath(transactionID)
	var stage stagedJoin
	if err := readJSON(path, &stage); err != nil {
		return stagedJoin{}, path, fmt.Errorf("invitation store: load stage: %w", err)
	}
	if stage.Version != membershipStoreVersion || stage.TransactionID != transactionID {
		return stagedJoin{}, path, errors.New("invitation store: corrupt staged transaction")
	}
	return stage, path, nil
}

func (s *FileStore) loadIndex() (membershipIndex, error) {
	index := membershipIndex{Version: membershipStoreVersion}
	err := readJSON(filepath.Join(s.root, "memberships.json"), &index)
	if errors.Is(err, os.ErrNotExist) {
		return index, nil
	}
	if err != nil {
		return membershipIndex{}, fmt.Errorf("invitation store: load index: %w", err)
	}
	if index.Version != membershipStoreVersion {
		return membershipIndex{}, errors.New("invitation store: unsupported index version")
	}
	return index, nil
}

func (s *FileStore) stagePath(transactionID string) string {
	sum := sha256.Sum256([]byte(transactionID))
	return filepath.Join(s.root, "staged", hex.EncodeToString(sum[:])+".json")
}

func readJSON(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return err
	}
	return nil
}

func atomicWriteJSON(path string, value any, mode os.FileMode) error {
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
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
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
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func nextAlias(name string, records []storedMembership) string {
	used := make([]string, 0, len(records))
	for _, record := range records {
		used = append(used, record.Membership.Alias)
	}
	return hubalias.Allocate(name, used)
}
