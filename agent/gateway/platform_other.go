//go:build !linux

package gateway

func newPlatformBackend() (Backend, error) {
	return nil, ErrPlatformUnsupported
}
