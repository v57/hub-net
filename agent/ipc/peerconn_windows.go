//go:build windows

package ipc

import (
	"net"

	"github.com/v57/hub-net/localsock"
)

// readPeer maps a named-pipe client to a uid (localsock.PeerUID): 0 for
// LocalSystem and elevated Administrators, os.Getuid() (-1) for the agent's
// own account, 1 for anyone else.
func readPeer(conn net.Conn) (int, bool) {
	uid, err := localsock.PeerUID(conn)
	return uid, err == nil
}
