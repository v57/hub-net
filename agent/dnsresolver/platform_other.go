//go:build !linux

package dnsresolver

import (
	"context"
	"errors"
	"net"
)

var errPlatformInstallerUnsupported = errors.New("dnsresolver: split DNS unsupported on this platform")

type unsupportedInstaller struct{}

func newPlatformInstaller(string) Installer { return unsupportedInstaller{} }

func (unsupportedInstaller) Install(context.Context, net.Addr, string) error {
	return errPlatformInstallerUnsupported
}

func (unsupportedInstaller) Remove(context.Context) error { return nil }
