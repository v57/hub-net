//go:build linux

package dnsresolver

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestResolvedInstallerLifecycle(t *testing.T) {
	var calls [][]string
	installer := &resolvedInstaller{
		interfaceName: "lo",
		run: func(_ context.Context, name string, args ...string) error {
			calls = append(calls, append([]string{name}, args...))
			return nil
		},
	}
	address := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53001}
	if err := installer.Install(context.Background(), address, Suffix); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := installer.Remove(context.Background()); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	want := [][]string{
		{"resolvectl", "dns", "lo", "127.0.0.1:53001"},
		{"resolvectl", "domain", "lo", "~hub.invalid"},
		{"resolvectl", "default-route", "lo", "no"},
		{"resolvectl", "revert", "lo"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
}

func TestResolvedInstallerReportsLiveCommandFailure(t *testing.T) {
	bin := t.TempDir()
	resolvectl := filepath.Join(bin, "resolvectl")
	const marker = "HN621_SYSTEMD_RESOLVED_FAILURE"
	if err := os.WriteFile(
		resolvectl,
		[]byte("#!/bin/sh\necho "+marker+" >&2\nexit 19\n"),
		0o755,
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	installer := newPlatformInstaller("hubnet0")
	err := installer.Install(context.Background(), &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"), Port: 53001,
	}, Suffix)
	if err == nil || !strings.Contains(err.Error(), marker) {
		t.Fatalf("error = %v, want %s", err, marker)
	}
}

func TestResolvedInstallerPrivilegedLifecycle(t *testing.T) {
	if os.Getenv("HUB_NET_PRIVILEGED") == "" || os.Geteuid() != 0 {
		t.Skip("set HUB_NET_PRIVILEGED=1 and run as root")
	}
	const interfaceName = "hubdnstest"
	_ = exec.Command("ip", "link", "del", interfaceName).Run()
	if output, err := exec.Command("ip", "link", "add", interfaceName, "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("create test interface: %v: %s", err, output)
	}
	t.Cleanup(func() {
		_ = exec.Command("resolvectl", "revert", interfaceName).Run()
		_ = exec.Command("ip", "link", "del", interfaceName).Run()
	})

	installer := newPlatformInstaller(interfaceName)
	address := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53001}
	if err := installer.Install(context.Background(), address, Suffix); err != nil {
		t.Fatalf("Install: %v", err)
	}
	status, err := exec.Command("resolvectl", "status", interfaceName).CombinedOutput()
	if err != nil {
		t.Fatalf("resolvectl status: %v: %s", err, status)
	}
	for _, want := range []string{"~hub.invalid", "127.0.0.1:53001", "Default Route: no"} {
		if !strings.Contains(string(status), want) {
			t.Fatalf("status missing %q:\n%s", want, status)
		}
	}
	if err := installer.Remove(context.Background()); err != nil {
		t.Fatalf("Remove: %v", err)
	}
}

func TestResolvedInstallerRollsBackPartialInstall(t *testing.T) {
	var calls [][]string
	installer := &resolvedInstaller{
		interfaceName: "lo",
		run: func(_ context.Context, name string, args ...string) error {
			call := append([]string{name}, args...)
			calls = append(calls, call)
			if len(args) > 0 && args[0] == "domain" {
				return errors.New("injected failure")
			}
			return nil
		},
	}
	err := installer.Install(context.Background(), &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"), Port: 53001,
	}, Suffix)
	if err == nil {
		t.Fatal("Install unexpectedly succeeded")
	}
	last := calls[len(calls)-1]
	if !reflect.DeepEqual(last, []string{"resolvectl", "revert", "lo"}) {
		t.Fatalf("last call = %#v, want revert", last)
	}
}
