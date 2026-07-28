// peeruid_linux.go reads the peer effective uid via SO_PEERCRED.
package ipc

import "golang.org/x/sys/unix"

func peerUIDFromFD(fd int) (int, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(cred.Uid), nil
}
