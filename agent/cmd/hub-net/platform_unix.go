//go:build !windows

package main

import (
	"context"
	"errors"
)

func runAsService(func(context.Context) error) (bool, error) { return false, nil }

func serviceCommand([]string, []string) error {
	return errors.New("service: Windows only; on Linux install the package's systemd unit")
}

// prepareStateDir leaves the state directory to the package (systemd's
// StateDirectory, mode 0700).
func prepareStateDir(string) error { return nil }

// defaultDeviceKey leaves the device key to hub-service's lookup.
func defaultDeviceKey() string { return "" }
