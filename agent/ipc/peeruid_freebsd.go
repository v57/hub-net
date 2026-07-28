// peeruid_freebsd.go reads the peer effective uid via LOCAL_PEERCRED.
package ipc

import "golang.org/x/sys/unix"

func peerUIDFromFD(fd int) (int, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(cred.Uid), nil
}
