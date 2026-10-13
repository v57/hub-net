// Package version reports the hub-net agent build version.
//
// Version is the wire-compatible Hub Network major version the agent speaks
// plus a build identifier. The first release advertises Hub Network major
// version 1; see protocol-foundations.md for the frozen constants.
package version

import (
	"fmt"

	protocol "github.com/v57/hub-net-node/models"
)

// Major is the Hub Network protocol major version implemented by this agent.
const Major = protocol.WireVersion

// Minor is the implemented Hub Network protocol minor version.
const Minor = 0

// Build is the agent build identifier. Overridden at link time with
// `-ldflags "-X github.com/v57/hub-net/version.Build=..."`.
var Build = "dev"

// String returns a "major.minor+build" identifier suitable for status APIs.
func String() string { return fmt.Sprintf("%d.%d+%s", Major, Minor, Build) }
