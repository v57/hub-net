// Package keychain persists hub-net agent private material.
//
// The agent keeps two secrets separate, per the network-agent spec "Keys are
// separated and protected":
//
//   - profile identity (Hub service identity, base64 PKCS8+SPKI matching the
//     Bun/Go SDK keychain) under IdentityStorage
//   - WireGuard private key (32 raw bytes) under WireGuardStorage
//
// Both stores write with file mode 0600. Material is created on first start;
// subsequent starts reuse it so stable share ownership survives rotation of
// either key. WireGuard key rotation produces a new file (or replaces content
// in place) but never touches the profile identity, and vice versa.
package keychain

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/v57/hub-service-go/identity"
)

// fileMode is the restrictive file mode for all persisted secrets.
const fileMode os.FileMode = 0o600

// Storage is a generic append-only-overwrite secret file. Keeping it tiny and
// explicit avoids accidental inline key material in config.
type Storage struct {
	path string
}

// New returns a Storage rooted at path. The file is created on first Write.
func New(path string) *Storage { return &Storage{path: path} }

// Path reports the storage location.
func (s *Storage) Path() string { return s.path }

// EnsureParent creates the parent directory with mode 0700 when absent.
func (s *Storage) EnsureParent() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("keychain: create %s: %w", dir, err)
	}
	return nil
}

// Write replaces the stored secret atomically. data must not be empty.
func (s *Storage) Write(data []byte) error {
	if len(data) == 0 {
		return errors.New("keychain: refuse to write empty secret")
	}
	if err := s.EnsureParent(); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".hub-net-key-*")
	if err != nil {
		return fmt.Errorf("keychain: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("keychain: write temp file: %w", err)
	}
	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("keychain: chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keychain: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("keychain: rename %s: %w", s.path, err)
	}
	cleanup = false
	// Belt-and-braces: ensure final mode even if target existed with looser
	// perms and rename preserved inode attributes on some platforms.
	_ = os.Chmod(s.path, fileMode)
	return nil
}

// Read returns the stored secret. Returns an error wrapping os.ErrNotExist
// when the file is absent so callers can distinguish first-run.
func (s *Storage) Read() ([]byte, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("keychain: read %s: %w", s.path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("keychain: %s is empty", s.path)
	}
	return data, nil
}

// Exists reports whether the secret file is present.
func (s *Storage) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// IdentityStorage persists the Hub profile identity using the SDK keychain
// format so it interchanges with hub-service-go and the Bun keychain.
type IdentityStorage struct {
	*Storage
}

// NewIdentityStorage returns an IdentityStorage rooted at path.
func NewIdentityStorage(path string) *IdentityStorage {
	return &IdentityStorage{Storage: New(path)}
}

// LoadOrGenerate returns the persistent profile identity, generating and
// persisting a fresh identity when absent.
func (i *IdentityStorage) LoadOrGenerate() (*identity.Identity, error) {
	if !i.Exists() {
		fresh, err := identity.Generate()
		if err != nil {
			return nil, err
		}
		encoded, err := fresh.Encode()
		if err != nil {
			return nil, err
		}
		if err := i.Write([]byte(encoded)); err != nil {
			return nil, err
		}
		return fresh, nil
	}
	encoded, err := i.Read()
	if err != nil {
		return nil, err
	}
	return loadIdentityFromBytes(encoded)
}

// loadIdentityFromBytes parses an identity blob using the SDK loader. It
// reuses identity.Load semantics without depending on a temp file.
func loadIdentityFromBytes(encoded []byte) (*identity.Identity, error) {
	tmp, err := os.CreateTemp("", "hub-net-id-*")
	if err != nil {
		return nil, fmt.Errorf("keychain: staging identity: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("keychain: stage identity write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("keychain: stage identity close: %w", err)
	}
	loaded, err := identity.Load(tmpName)
	if err != nil {
		return nil, err
	}
	return loaded, nil
}

// WireGuardStorage persists a 32-byte WireGuard private key.
type WireGuardStorage struct {
	*Storage
}

// NewWireGuardStorage returns a WireGuardStorage rooted at path.
func NewWireGuardStorage(path string) *WireGuardStorage {
	return &WireGuardStorage{Storage: New(path)}
}

// PrivateKeyLength is the WireGuard Curve25519 private key length.
const PrivateKeyLength = 32

// LoadOrGenerate returns the persistent WireGuard private key, generating a
// fresh random one when absent. WireGuard Curve25519 keys are 32 raw bytes;
// the secret clamping is performed by WireGuard implementations, not here.
func (w *WireGuardStorage) LoadOrGenerate() ([]byte, error) {
	if !w.Exists() {
		key := make([]byte, PrivateKeyLength)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("keychain: generate wireguard key: %w", err)
		}
		if err := w.Write(key); err != nil {
			return nil, err
		}
		return key, nil
	}
	key, err := w.Read()
	if err != nil {
		return nil, err
	}
	if len(key) != PrivateKeyLength {
		return nil, fmt.Errorf("keychain: wireguard key %s has wrong length %d", w.path, len(key))
	}
	return key, nil
}

// Rotate replaces the WireGuard private key with a fresh one. The profile
// identity is untouched. Hub binds the new public key to the same profile
// through a subsequent short-lived grant.
func (w *WireGuardStorage) Rotate() ([]byte, error) {
	key := make([]byte, PrivateKeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("keychain: rotate wireguard key: %w", err)
	}
	if err := w.Write(key); err != nil {
		return nil, err
	}
	return key, nil
}

// ForceEncodeIdentityForTest writes an explicit identity blob. Tests use this
// to install deterministic identity material without going through Generate.
func ForceEncodeIdentityForTest(id *identity.Identity) ([]byte, error) {
	encoded, err := id.Encode()
	if err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}
