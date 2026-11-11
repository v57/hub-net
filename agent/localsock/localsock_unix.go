//go:build !windows

package localsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
)

// Path is the endpoint for path: the socket file itself on Unix.
func Path(path string) string { return path }

// Listen removes a stale socket left by a crash, binds path and applies
// access to the socket file.
func Listen(path string, access Access) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("localsock: remove stale socket %s: %w", path, err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := apply(path, access); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, err
	}
	return listener, nil
}

func apply(path string, access Access) error {
	mode := os.FileMode(access.Mode)
	if mode == 0 {
		mode = 0o600
	}
	if access.Group != "" {
		group, err := user.LookupGroup(access.Group)
		if err != nil {
			return fmt.Errorf("localsock: socket group %q: %w", access.Group, err)
		}
		gid, err := strconv.Atoi(group.Gid)
		if err != nil {
			return fmt.Errorf("localsock: socket group %q: %w", access.Group, err)
		}
		if err := os.Chown(path, -1, gid); err != nil {
			return err
		}
		mode = 0o660
	}
	return os.Chmod(path, mode)
}

// Remove deletes the socket file after the listener closed.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Dial connects to the socket at path.
func Dial(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}
