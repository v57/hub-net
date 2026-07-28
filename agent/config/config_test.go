package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveFillsDefaults(t *testing.T) {
	var cfg Config
	if err := cfg.Resolve(); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.HubAddress != DefaultHubPort {
		t.Fatalf("HubAddress = %v, want %d", cfg.HubAddress, DefaultHubPort)
	}
	if cfg.StateDir == "" {
		t.Fatalf("StateDir empty")
	}
	if cfg.IdentityPath == "" || !filepath.IsAbs(cfg.IdentityPath) {
		t.Fatalf("IdentityPath invalid: %s", cfg.IdentityPath)
	}
	if cfg.WireGuardKeyPath == "" || !filepath.IsAbs(cfg.WireGuardKeyPath) {
		t.Fatalf("WireGuardKeyPath invalid: %s", cfg.WireGuardKeyPath)
	}
	if cfg.AgentSocketPath == "" {
		t.Fatalf("AgentSocketPath empty")
	}
}

func TestResolveRejectsRelativeKeyPaths(t *testing.T) {
	cfg := Defaults()
	cfg.IdentityPath = "relative.identity"
	err := cfg.Resolve()
	if err == nil || !strings.Contains(err.Error(), "identityPath") {
		t.Fatalf("expected identityPath error, got %v", err)
	}
}

func TestEnsureStateDirCreatesDir(t *testing.T) {
	cfg := Config{StateDir: filepath.Join(t.TempDir(), "state")}
	if err := cfg.EnsureStateDir(); err != nil {
		t.Fatalf("EnsureStateDir: %v", err)
	}
	info, err := statMode(cfg.StateDir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode = %v, want 0700", info.Mode().Perm())
	}
}

func TestDefaultsAreSensible(t *testing.T) {
	cfg := Defaults()
	if cfg.AttestationTTL <= 0 {
		t.Fatalf("AttestationTTL not positive")
	}
	if cfg.PeerIdleTimeout <= 0 {
		t.Fatalf("PeerIdleTimeout not positive")
	}
	if cfg.HandshakeTimeout <= 0 {
		t.Fatalf("HandshakeTimeout not positive")
	}
}
