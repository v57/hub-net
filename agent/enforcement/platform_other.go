//go:build !linux

package enforcement

func newPlatformBackend(string) (Backend, error) {
	return nil, ErrPlatformUnsupported
}
