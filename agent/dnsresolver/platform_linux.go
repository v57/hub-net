//go:build linux

package dnsresolver

import (
	"context"
	"fmt"
	"net"
	"os/exec"
)

type commandRunner func(context.Context, string, ...string) error

type resolvedInstaller struct {
	interfaceName string
	run           commandRunner
}

func newPlatformInstaller(interfaceName string) Installer {
	return &resolvedInstaller{interfaceName: interfaceName, run: runCommand}
}

func runCommand(ctx context.Context, name string, args ...string) error {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, output)
	}
	return nil
}

func (i *resolvedInstaller) Install(ctx context.Context, address net.Addr, suffix string) error {
	udp, ok := address.(*net.UDPAddr)
	if !ok || udp.IP == nil || udp.Port == 0 {
		return fmt.Errorf("dnsresolver: invalid local DNS address %v", address)
	}
	server := net.JoinHostPort(udp.IP.String(), fmt.Sprint(udp.Port))
	if err := i.run(ctx, "resolvectl", "dns", i.interfaceName, server); err != nil {
		return err
	}
	rollback := func() { _ = i.run(context.Background(), "resolvectl", "revert", i.interfaceName) }
	if err := i.run(ctx, "resolvectl", "domain", i.interfaceName, "~"+suffix); err != nil {
		rollback()
		return err
	}
	if err := i.run(ctx, "resolvectl", "default-route", i.interfaceName, "no"); err != nil {
		rollback()
		return err
	}
	return nil
}

func (i *resolvedInstaller) Remove(ctx context.Context) error {
	return i.run(ctx, "resolvectl", "revert", i.interfaceName)
}
