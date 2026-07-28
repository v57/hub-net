//go:build !linux

package enforcement

import (
	"errors"
	"testing"
)

func TestPlatformBackendFailsClosedWhenUnsupported(t *testing.T) {
	backend, err := NewPlatformBackend("hubnet0")
	if backend != nil || !errors.Is(err, ErrPlatformUnsupported) {
		t.Fatalf("backend = %T, error = %v", backend, err)
	}
}

func TestPlatformBackendRejectsEmptyInterface(t *testing.T) {
	backend, err := NewPlatformBackend("")
	if backend != nil || !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("backend = %T, error = %v", backend, err)
	}
}
