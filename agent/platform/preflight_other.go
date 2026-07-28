//go:build !linux

package platform

import (
	"fmt"
	"runtime"
)

func preflight() error {
	return fmt.Errorf("%w: %s has no packaged Go tunnel adapter", ErrUnsupported, runtime.GOOS)
}
