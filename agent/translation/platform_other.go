//go:build !linux

package translation

import "errors"

var ErrPlatformUnsupported = errors.New("translation: platform unsupported")

func newPlatformBackend() (Backend, error) {
	return nil, ErrPlatformUnsupported
}
