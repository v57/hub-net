//go:build !linux

package wireguard

import "net/netip"

// SendFromPort is unavailable without kernel WireGuard.
func SendFromPort(uint16, netip.AddrPort, []byte) error { return ErrPlatformUnsupported }
