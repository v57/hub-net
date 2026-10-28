//go:build linux

package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type runner interface {
	Run(name string, input []byte, args ...string) error
}

type commandRunner struct{}

func (commandRunner) Run(name string, input []byte, args ...string) error {
	command := exec.Command(name, args...)
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

type linuxBackend struct {
	mu      sync.Mutex
	runner  runner
	enabled bool
	table   string
}

var forwarding = struct {
	sync.Mutex
	users   int
	ipv4Old string
	ipv6Old string
}{}

func newPlatformBackend() (Backend, error) {
	return &linuxBackend{runner: commandRunner{}}, nil
}

func (b *linuxBackend) Enable(config Config) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.enabled {
		return nil
	}
	if config.InterfaceName == "" {
		return errors.New("gateway: interface name required")
	}
	if err := acquireForwarding(b.runner); err != nil {
		return err
	}
	table := tableName(config.InterfaceName)
	// Repair stale state from interrupted shutdown without touching siblings.
	_ = b.runner.Run("nft", nil, "delete", "table", "inet", table)
	if err := b.runner.Run("nft", []byte(rules(config, table)), "-f", "-"); err != nil {
		_ = releaseForwarding(b.runner)
		return err
	}
	b.table, b.enabled = table, true
	return nil
}

func (b *linuxBackend) Disable() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enabled {
		return nil
	}
	// Deleting owned table removes forwarding, NAT, and conntrack acceptance
	// immediately. Conntrack entries are then flushed for gateway source ranges.
	var result error
	result = errors.Join(result, b.runner.Run("nft", nil, "delete", "table", "inet", b.table))
	// No matching flow makes conntrack return non-zero; deletion remains best effort.
	_ = b.runner.Run("conntrack", nil, "-D", "-s", "100.96.0.0/11")
	_ = b.runner.Run("conntrack", nil, "-D", "-s", "fd48:5542:4e45::/48")
	result = errors.Join(result, releaseForwarding(b.runner))
	b.enabled = false
	return result
}

func acquireForwarding(run runner) error {
	forwarding.Lock()
	defer forwarding.Unlock()
	if forwarding.users > 0 {
		forwarding.users++
		return nil
	}
	ipv4Old, err := sysctlRead(run, "net.ipv4.ip_forward")
	if err != nil {
		return err
	}
	ipv6Old, err := sysctlRead(run, "net.ipv6.conf.all.forwarding")
	if err != nil {
		return err
	}
	if err := run.Run("sysctl", nil, "-q", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	if err := run.Run("sysctl", nil, "-q", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
		_ = run.Run("sysctl", nil, "-q", "-w", "net.ipv4.ip_forward="+ipv4Old)
		return err
	}
	forwarding.ipv4Old, forwarding.ipv6Old, forwarding.users = ipv4Old, ipv6Old, 1
	return nil
}

func releaseForwarding(run runner) error {
	forwarding.Lock()
	defer forwarding.Unlock()
	if forwarding.users == 0 {
		return nil
	}
	forwarding.users--
	if forwarding.users > 0 {
		return nil
	}
	result := errors.Join(
		run.Run("sysctl", nil, "-q", "-w", "net.ipv4.ip_forward="+forwarding.ipv4Old),
		run.Run("sysctl", nil, "-q", "-w", "net.ipv6.conf.all.forwarding="+forwarding.ipv6Old),
	)
	forwarding.ipv4Old, forwarding.ipv6Old = "", ""
	return result
}

func sysctlRead(run runner, key string) (string, error) {
	capture := &captureRunner{runner: run}
	if err := capture.Run("sysctl", nil, "-n", key); err != nil {
		return "", err
	}
	value := strings.TrimSpace(capture.output.String())
	if value != "0" && value != "1" {
		return "", fmt.Errorf("gateway: invalid %s value %q", key, value)
	}
	return value, nil
}

type captureRunner struct {
	runner runner
	output bytes.Buffer
}

func (r *captureRunner) Run(name string, input []byte, args ...string) error {
	if command, ok := r.runner.(commandRunner); ok {
		cmd := exec.Command(name, args...)
		cmd.Stdin = bytes.NewReader(input)
		cmd.Stdout = &r.output
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
		}
		_ = command
		return nil
	}
	return r.runner.Run(name, input, args...)
}

func tableName(interfaceName string) string {
	return "hub_gw_" + strings.ReplaceAll(interfaceName, "-", "_")
}

func rules(config Config, table string) string {
	var output strings.Builder
	fmt.Fprintf(&output, "table inet %s {\n", table)
	output.WriteString(" chain input { type filter hook input priority -10; policy accept;\n")
	fmt.Fprintf(&output, "  iifname %q ct state invalid drop\n", config.InterfaceName)
	fmt.Fprintf(&output, "  iifname %q icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept\n", config.InterfaceName)
	// Answers to this host's own connections over the Hub Network, such as
	// its connection to the hub, keep arriving
	fmt.Fprintf(&output, "  iifname %q ct state established,related accept\n", config.InterfaceName)
	for _, port := range config.ManagementPorts {
		fmt.Fprintf(&output, "  iifname %q meta l4proto { tcp, udp } th dport %s drop\n", config.InterfaceName, strconv.Itoa(int(port)))
	}
	for _, address := range config.LocalAddresses {
		family := "ip"
		if address.Is6() {
			family = "ip6"
		}
		fmt.Fprintf(&output, "  iifname %q %s daddr %s accept\n", config.InterfaceName, family, address.Unmap())
	}
	for _, prefix := range config.ProtectedIPv4 {
		fmt.Fprintf(&output, "  iifname %q ip daddr %s drop\n", config.InterfaceName, prefix)
	}
	for _, prefix := range config.ProtectedIPv6 {
		fmt.Fprintf(&output, "  iifname %q ip6 daddr %s drop\n", config.InterfaceName, prefix)
	}
	fmt.Fprintf(&output, "  iifname %q drop\n", config.InterfaceName)
	output.WriteString(" }\n")
	output.WriteString(" chain forward { type filter hook forward priority -10; policy accept;\n")
	fmt.Fprintf(&output, "  iifname %q ct state invalid drop\n", config.InterfaceName)
	fmt.Fprintf(&output, "  oifname %q ct state established,related accept\n", config.InterfaceName)
	for _, prefix := range config.ProtectedIPv4 {
		fmt.Fprintf(&output, "  iifname %q ip daddr %s drop\n", config.InterfaceName, prefix)
	}
	for _, prefix := range config.ProtectedIPv6 {
		fmt.Fprintf(&output, "  iifname %q ip6 daddr %s drop\n", config.InterfaceName, prefix)
	}
	for _, port := range config.ManagementPorts {
		fmt.Fprintf(&output, "  iifname %q meta l4proto { tcp, udp } th dport %s drop\n", config.InterfaceName, strconv.Itoa(int(port)))
	}
	fmt.Fprintf(&output, "  iifname %q ip saddr %s accept\n", config.InterfaceName, config.CanonicalIPv4)
	fmt.Fprintf(&output, "  iifname %q ip6 saddr %s accept\n", config.InterfaceName, config.CanonicalIPv6)
	fmt.Fprintf(&output, "  iifname %q drop\n", config.InterfaceName)
	output.WriteString(" }\n")
	output.WriteString(" chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n")
	fmt.Fprintf(&output, "  iifname %q ip saddr %s ip daddr != %s masquerade\n", config.InterfaceName, config.CanonicalIPv4, config.CanonicalIPv4)
	fmt.Fprintf(&output, "  iifname %q ip6 saddr %s ip6 daddr != %s masquerade\n", config.InterfaceName, config.CanonicalIPv6, config.CanonicalIPv6)
	output.WriteString(" }\n}\n")
	return output.String()
}
