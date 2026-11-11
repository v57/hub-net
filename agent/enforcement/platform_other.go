//go:build !linux && !windows

package enforcement

func newPlatformBackend(string) (Backend, error) {
	return nil, ErrPlatformUnsupported
}
