// platform.go dispatches to the per-OS WireGuard adapter implementation.
//
// NewPlatformAdapter returns a real adapter on platforms with an
// implementation (Linux kernel netlink) and an unsupportedAdapter everywhere
// else. The unsupported variant fails safely on every call, satisfying the
// network-agent spec "Unsupported platforms fail safely": the agent reports
// unavailable and never advertises a working route.
//
// The per-OS constructor newOSAdapter lives in platform_linux.go (returns a
// *linuxAdapter) and platform_other.go (returns *unsupportedAdapter). Both
// share this dispatch entry point.

package wireguard

import "errors"

// ErrPlatformUnsupported signals that no real WireGuard adapter exists for the
// current build target. Callers SHOULD treat it as a configuration error and
// fall back to NewFakeAdapter for tests, or refuse to advertise a profile.
var ErrPlatformUnsupported = errors.New("wireguard: platform adapter unsupported")

// ErrNotImplemented signals a recognized platform whose adapter is planned but
// not yet wired (e.g. macOS privileged helper). Distinct from
// ErrPlatformUnsupported so callers can distinguish "never" from "later".
var ErrNotImplemented = errors.New("wireguard: platform adapter not implemented")

// NewPlatformAdapter returns the real WireGuard adapter for the current OS, or
// an adapter whose methods return ErrPlatformUnsupported when none exists. name
// is the OS interface name to manage (e.g. "hubnet0").
func NewPlatformAdapter(name string) Adapter {
	return newOSAdapter(name)
}

// ProbePlatformSupport verifies that the host exposes the platform tunnel
// facility without creating an interface or changing routes.
func ProbePlatformSupport() error {
	return probeOSSupport()
}
