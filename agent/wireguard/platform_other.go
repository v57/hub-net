// platform_other.go is the non-Linux dispatch target. No in-kernel WireGuard
// exists on these platforms (macOS needs a privileged userspace helper, Windows
// needs WireGuardNT). Until a real adapter lands, every operation fails safely
// with ErrPlatformUnsupported so the agent never advertises a working profile.

//go:build !linux

package wireguard

// unsupportedAdapter fails every operation. It is the safe fallback for
// platforms without a real WireGuard implementation.
type unsupportedAdapter struct {
	name string
}

// newOSAdapter returns an unsupportedAdapter on non-Linux builds.
func newOSAdapter(name string) Adapter {
	return &unsupportedAdapter{name: name}
}

func probeOSSupport() error { return ErrPlatformUnsupported }

// Up always fails: no real adapter exists on this platform.
func (u *unsupportedAdapter) Up(InterfaceConfig) error { return ErrPlatformUnsupported }

// Down always fails.
func (u *unsupportedAdapter) Down() error { return ErrPlatformUnsupported }

// AddPeer always fails.
func (u *unsupportedAdapter) AddPeer(PeerConfig) error { return ErrPlatformUnsupported }

// RemovePeer always fails.
func (u *unsupportedAdapter) RemovePeer([]byte) error { return ErrPlatformUnsupported }

// State reports down with no configuration.
func (u *unsupportedAdapter) State() (InterfaceConfig, bool) { return InterfaceConfig{}, false }
