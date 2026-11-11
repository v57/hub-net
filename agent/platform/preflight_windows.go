//go:build windows

package platform

import (
	"fmt"

	"github.com/v57/hub-net/wireguard"
	"golang.org/x/sys/windows"
)

// preflight requires an elevated token (the packaged service runs as
// LocalSystem) and a loadable WireGuardNT (wireguard.dll next to hub-net.exe
// or in System32).
func preflight() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("%w: run hub-net as the installed service (hub-net service install) or from an elevated shell", ErrMissingPrivileges)
	}
	if err := wireguard.ProbePlatformSupport(); err != nil {
		return fmt.Errorf("%w: %v", ErrTunnelUnavailable, err)
	}
	return nil
}
