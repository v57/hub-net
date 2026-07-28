//go:build !linux

package wireguard

import "testing"

// newUnsupportedAdapterForTest returns an unsupportedAdapter on non-Linux
// builds. On Linux the type does not exist; see platform_test_linux.go.
func newUnsupportedAdapterForTest(t *testing.T) Adapter {
	t.Helper()
	return &unsupportedAdapter{name: "hubnet0"}
}
