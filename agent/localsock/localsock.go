// Package localsock is the local IPC endpoint under the agent's service and
// command sockets: a Unix-domain socket on Linux and macOS, a named pipe on
// Windows (PLATFORMS.md). Listen applies the access rule at creation, Dial
// connects a client, and PeerUID names the connecting peer for the ipc
// package's peer check.
package localsock

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Access is who may connect besides the agent itself and the platform's
// administrators (root on Unix; SYSTEM and elevated Administrators on
// Windows).
type Access struct {
	// Group is a local group whose members may connect too (owner and group
	// read-write, mode 0660 on Unix; a read-write ACE on Windows). Empty
	// leaves the owner-only rule (mode 0600, or Mode when set).
	Group string
	// Mode is the Unix socket mode without a group. Zero means 0600. Unused
	// on Windows.
	Mode uint32
}

// pipeName is the Windows pipe for a socket path that isn't a pipe already:
// \\.\pipe\hub-net-<base>-<hash of the directory>, so each state directory
// (each membership) gets its own pipe.
func pipeName(path string) string {
	directory, base := path, "socket"
	if index := strings.LastIndexAny(path, `/\`); index >= 0 {
		directory, base = path[:index], path[index+1:]
	}
	base = strings.TrimSuffix(base, ".sock")
	sum := sha256.Sum256([]byte(strings.ToLower(directory)))
	return `\\.\pipe\hub-net-` + base + "-" + hex.EncodeToString(sum[:8])
}

// IsPipe reports whether path already names a Windows named pipe.
func IsPipe(path string) bool {
	return strings.HasPrefix(path, `\\.\pipe\`)
}
