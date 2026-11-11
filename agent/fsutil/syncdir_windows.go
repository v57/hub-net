//go:build windows

package fsutil

// SyncDir does nothing on Windows: a directory can't be opened for
// FlushFileBuffers (it fails with Access is denied), and NTFS journals the
// rename's metadata itself.
func SyncDir(string) error { return nil }
