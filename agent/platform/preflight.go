// Package platform performs production startup checks before hub-net
// registers a reachable profile with the Hub.
package platform

import "errors"

var (
	ErrUnsupported       = errors.New("platform: hub-net is unsupported")
	ErrMissingPrivileges = errors.New("platform: missing network privileges")
	ErrTunnelUnavailable = errors.New("platform: tunnel setup unavailable")
)

// Preflight verifies required platform privileges without mutating host state.
func Preflight() error { return preflight() }
