//go:build linux

package platform

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/v57/hub-net/wireguard"
)

const (
	capNetAdmin = 12
	capNetRaw   = 13
)

func preflight() error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("%w: read /proc/self/status: %v", ErrMissingPrivileges, err)
	}
	effective, err := effectiveCapabilities(string(data))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMissingPrivileges, err)
	}
	missing := missingCapabilities(effective)
	if len(missing) > 0 {
		return fmt.Errorf(
			"%w: missing %s; install the packaged systemd unit or add these capabilities to the service",
			ErrMissingPrivileges,
			strings.Join(missing, ", "),
		)
	}
	if err := wireguard.ProbePlatformSupport(); err != nil {
		return fmt.Errorf("%w: %v", ErrTunnelUnavailable, err)
	}
	return nil
}

func missingCapabilities(effective uint64) []string {
	var missing []string
	if effective&(1<<capNetAdmin) == 0 {
		missing = append(missing, "CAP_NET_ADMIN")
	}
	if effective&(1<<capNetRaw) == 0 {
		missing = append(missing, "CAP_NET_RAW")
	}
	return missing
}

func effectiveCapabilities(status string) (uint64, error) {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			return strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		}
	}
	return 0, fmt.Errorf("CapEff missing from /proc/self/status")
}
