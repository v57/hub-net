//go:build !windows

package ipc

import "net"

// readPeer reads a Unix socket peer's uid; ok is false for other
// connections and when the credentials can't be read.
func readPeer(conn net.Conn) (int, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	uid, err := readPeerUID(uc)
	return uid, err == nil
}

// readPeerUID reads the connecting peer's effective uid via the platform's
// peer-credential socket option.
func readPeerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid int
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		uid, sockErr = peerUIDFromFD(int(fd))
	})
	if ctrlErr != nil {
		return 0, ctrlErr
	}
	return uid, sockErr
}
