package config

import "os"

// statMode returns the os.FileInfo for path. Kept in a test-only file so the
// non-test build does not pull os.Stat into the package surface.
func statMode(path string) (os.FileInfo, error) { return os.Stat(path) }
