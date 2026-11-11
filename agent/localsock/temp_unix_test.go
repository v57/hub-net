//go:build !windows

package localsock

import (
	"os"
	"testing"
)

func filepathTemp() (string, error) { return os.MkdirTemp("/tmp", "ls") }
func removeAll(dir string)          { os.RemoveAll(dir) }

func TestListenAppliesMode(t *testing.T) {
	dir, err := filepathTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer removeAll(dir)
	path := dir + "/mode.sock"
	listener, err := Listen(path, Access{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	// A stale socket from a crash is replaced.
	listener.Close()
	again, err := Listen(path, Access{Mode: 0o660})
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	defer again.Close()
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o660 {
		t.Fatalf("mode = %o, want 660", info.Mode().Perm())
	}
}
