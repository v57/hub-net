// peeruid_other.go is the fallback for platforms without peer-credential
// socket options. Peer enforcement there must rely entirely on the socket's
// filesystem permissions; VerifyLocalPeer returns ErrPeerUnknown unless
// PeerPolicy.AllowAnyLocal is set.
//go:build !linux && !darwin && !freebsd

package ipc

func peerUIDFromFD(fd int) (int, error) { return 0, ErrPeerUnknown }
