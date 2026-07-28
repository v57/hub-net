// Package config defines hub-net agent configuration.
//
// The agent reads a single configuration document. Sensitive inputs (identity
// path, WireGuard key path) are file paths, never inline material; the agent
// loads them through keychain.Storage using platform file protection. The
// document is intentionally small: discovery, routing, DNS, IPC, and platform
// knobs come from PLATFORMS.md constants and the protocol-foundations frozen
// ranges.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/v57/hub-service-go/protocol"
)

// DefaultAgentSocketDarwin is the macOS hub-net agent IPC socket.
const DefaultAgentSocketDarwin = "/var/run/hub-net/agent.sock"

// DefaultAgentSocketLinux is the Linux hub-net agent IPC socket.
const DefaultAgentSocketLinux = "/run/hub-net/agent.sock"

// DefaultIdentityFile is the persistent profile identity file name within the
// state directory. Reuse the Bun/Go SDK 0600 storage convention.
const DefaultIdentityFile = "profile.identity"

// DefaultWireGuardKeyFile is the persistent WireGuard private key file name
// within the state directory.
const DefaultWireGuardKeyFile = "wireguard.key"

// DefaultHubPort matches hub-service-go DefaultHubAddress.
const DefaultHubPort = 1997

// DefaultStateDir is the per-platform agent state directory. Root-owned on
// Darwin/Linux so identity, key material, and runtime state are colocated.
func DefaultStateDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/var/lib/hub-net"
	case "linux":
		return "/var/lib/hub-net"
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "hub-net")
	default:
		return filepath.Join(os.TempDir(), "hub-net")
	}
}

// DefaultAgentSocket returns the platform-specific IPC socket path.
func DefaultAgentSocket() string {
	switch runtime.GOOS {
	case "linux":
		return DefaultAgentSocketLinux
	case "windows":
		return `\\.\pipe\hub-net-agent`
	default:
		return DefaultAgentSocketDarwin
	}
}

// Config is the hub-net agent configuration document.
type Config struct {
	// HubAddress is the Hub WebSocket address: integer port, "host:port", or
	// full "ws://" URL. Defaults to DefaultHubPort.
	HubAddress any `json:"hubAddress,omitempty"`
	// StateDir holds identity, WireGuard key, runtime database. Defaults to
	// DefaultStateDir().
	StateDir string `json:"stateDir,omitempty"`
	// IdentityPath overrides the profile identity file. Defaults to
	// StateDir/DefaultIdentityFile.
	IdentityPath string `json:"identityPath,omitempty"`
	// WireGuardKeyPath overrides the WireGuard private key file. Defaults to
	// StateDir/DefaultWireGuardKeyFile.
	WireGuardKeyPath string `json:"wireGuardKeyPath,omitempty"`
	// AgentSocketPath is the local IPC endpoint. Defaults to
	// DefaultAgentSocket().
	AgentSocketPath string `json:"agentSocketPath,omitempty"`
	// DNSListenAddress is the loopback UDP endpoint for reserved-suffix DNS.
	// Platform packaging directs only hub.invalid queries to this endpoint.
	DNSListenAddress string `json:"dnsListenAddress,omitempty"`
	// AttestationTTL is how long issued attestations remain valid. Must stay
	// short; Hub re-checks on every share registration.
	AttestationTTL time.Duration `json:"attestationTtl,omitempty"`
	// PeerIdleTimeout is how long an idle WireGuard peer state is kept before
	// removal. See network-agent spec "Agent manages peers on demand".
	PeerIdleTimeout time.Duration `json:"peerIdleTimeout,omitempty"`
	// HandshakeTimeout bounds a candidate/handshake attempt before the agent
	// reports direct-connect failure. No relay fallback.
	HandshakeTimeout time.Duration `json:"handshakeTimeout,omitempty"`
}

// Defaults returns a Config populated with documented defaults. Caller may
// override fields before calling Resolve.
func Defaults() Config {
	stateDir := DefaultStateDir()
	return Config{
		HubAddress:       DefaultHubPort,
		StateDir:         stateDir,
		IdentityPath:     filepath.Join(stateDir, DefaultIdentityFile),
		WireGuardKeyPath: filepath.Join(stateDir, DefaultWireGuardKeyFile),
		AgentSocketPath:  DefaultAgentSocket(),
		DNSListenAddress: "127.0.0.1:0",
		AttestationTTL:   2 * time.Minute,
		PeerIdleTimeout:  5 * time.Minute,
		HandshakeTimeout: 30 * time.Second,
	}
}

// Resolve fills empty fields with defaults and validates required ones. It
// does not touch the filesystem; keychain.Storage loads or creates material
// at agent start.
func (c *Config) Resolve() error {
	if c.HubAddress == nil {
		c.HubAddress = DefaultHubPort
	}
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir()
	}
	if c.IdentityPath == "" {
		c.IdentityPath = filepath.Join(c.StateDir, DefaultIdentityFile)
	}
	if c.WireGuardKeyPath == "" {
		c.WireGuardKeyPath = filepath.Join(c.StateDir, DefaultWireGuardKeyFile)
	}
	if c.AgentSocketPath == "" {
		c.AgentSocketPath = DefaultAgentSocket()
	}
	if c.DNSListenAddress == "" {
		c.DNSListenAddress = "127.0.0.1:0"
	}
	if c.AttestationTTL == 0 {
		c.AttestationTTL = 2 * time.Minute
	}
	if c.PeerIdleTimeout == 0 {
		c.PeerIdleTimeout = 5 * time.Minute
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 30 * time.Second
	}
	if !filepath.IsAbs(c.IdentityPath) {
		return fmt.Errorf("config: identityPath must be absolute: %s", c.IdentityPath)
	}
	if !filepath.IsAbs(c.WireGuardKeyPath) {
		return fmt.Errorf("config: wireGuardKeyPath must be absolute: %s", c.WireGuardKeyPath)
	}
	return nil
}

// EnsureStateDir creates StateDir with restrictive permissions when absent.
// Identity and WireGuard key material live beneath it; only the agent user
// should read it.
func (c *Config) EnsureStateDir() error {
	if c.StateDir == "" {
		return errors.New("config: stateDir empty (call Resolve first)")
	}
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return fmt.Errorf("config: create state dir %s: %w", c.StateDir, err)
	}
	return nil
}

// WireVersion exposes the Hub Network protocol version the agent speaks, for
// status reporting without importing protocol at call sites.
func WireVersion() int { return protocol.WireVersion }
