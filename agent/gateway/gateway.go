// Package gateway owns contained internet-gateway serving lifecycle.
package gateway

import (
	"errors"
	"net/netip"
	"sync"
)

var ErrPlatformUnsupported = errors.New("gateway: platform unsupported")

type Config struct {
	InterfaceName   string
	CanonicalIPv4   netip.Prefix
	CanonicalIPv6   netip.Prefix
	ProtectedIPv4   []netip.Prefix
	ProtectedIPv6   []netip.Prefix
	ManagementPorts []uint16
}

type Backend interface {
	Enable(Config) error
	Disable() error
}

// MemoryBackend provides deterministic lifecycle tests without privileges.
type MemoryBackend struct {
	mu      sync.Mutex
	Enabled bool
	Config  Config
	Flows   int
	Fail    error
}

func (b *MemoryBackend) Enable(config Config) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Fail != nil {
		return b.Fail
	}
	b.Config = config
	b.Enabled = true
	return nil
}

func (b *MemoryBackend) Disable() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Enabled = false
	b.Flows = 0
	return b.Fail
}

func DefaultConfig(interfaceName string) Config {
	return Config{
		InterfaceName: interfaceName,
		CanonicalIPv4: netip.MustParsePrefix("100.96.0.0/11"),
		CanonicalIPv6: netip.MustParsePrefix("fd48:5542:4e45::/48"),
		ProtectedIPv4: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/8"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("169.254.0.0/16"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("224.0.0.0/4"),
		},
		ProtectedIPv6: []netip.Prefix{
			netip.MustParsePrefix("::/128"),
			netip.MustParsePrefix("::1/128"),
			netip.MustParsePrefix("fc00::/7"),
			netip.MustParsePrefix("fe80::/10"),
			netip.MustParsePrefix("ff00::/8"),
		},
	}
}
