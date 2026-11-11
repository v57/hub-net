//go:build !windows

package fsutil

import "os"

// SyncDir flushes a directory's entries (a rename into it) to disk.
func SyncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
