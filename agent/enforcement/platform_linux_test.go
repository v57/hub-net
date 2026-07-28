//go:build linux

package enforcement

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recordingRunner struct {
	calls []runnerCall
}

func TestLinuxBackendReportsLiveDependencyFailures(t *testing.T) {
	t.Run("nftables", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		_, err := NewPlatformBackend("hubnet0")
		if err == nil || !strings.Contains(err.Error(), "enforcement: nftables unavailable") {
			t.Fatalf("error = %v, want nftables unavailable", err)
		}
	})

	t.Run("conntrack", func(t *testing.T) {
		bin := t.TempDir()
		nft := filepath.Join(bin, "nft")
		if err := os.WriteFile(nft, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin)
		_, err := NewPlatformBackend("hubnet0")
		if err == nil || !strings.Contains(err.Error(), "enforcement: conntrack unavailable") {
			t.Fatalf("error = %v, want conntrack unavailable", err)
		}
	})
}

func TestLinuxBackendPrivilegedLifecycle(t *testing.T) {
	if os.Getenv("HUB_NET_PRIVILEGED") == "" || os.Geteuid() != 0 {
		t.Skip("set HUB_NET_PRIVILEGED=1 and run as root")
	}
	_ = exec.Command("nft", "delete", "table", "inet", nftTable).Run()
	t.Cleanup(func() {
		_ = exec.Command("nft", "delete", "table", "inet", nftTable).Run()
	})

	backend, err := NewPlatformBackend("hubwgtest")
	if err != nil {
		t.Fatalf("NewPlatformBackend: %v", err)
	}
	rule := Rule{
		ResourceID:      "resource-test",
		ProviderID:      "provider-test",
		Source:          netip.MustParseAddr("100.96.0.3"),
		Destination:     netip.MustParseAddr("100.96.0.2"),
		DestinationPort: 9001,
		Protocol:        "tcp",
		Generation:      1,
		ExpiresAt:       time.Now().Add(time.Minute),
	}
	if err := backend.ReplaceRules([]Rule{rule}); err != nil {
		t.Fatalf("ReplaceRules: %v", err)
	}
	output, err := exec.Command("nft", "list", "table", "inet", nftTable).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v: %s", err, output)
	}
	for _, want := range []string{"iifname \"hubwgtest\"", "ip saddr 100.96.0.3", "tcp dport 9001", "drop"} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("ruleset missing %q:\n%s", want, output)
		}
	}
	if err := backend.ReplaceRules(nil); err != nil {
		t.Fatalf("clear rules: %v", err)
	}
}

type runnerCall struct {
	name  string
	args  []string
	stdin string
}

func (r *recordingRunner) run(name string, args []string, stdin string) error {
	r.calls = append(r.calls, runnerCall{name: name, args: append([]string(nil), args...), stdin: stdin})
	return nil
}

func TestNFTScriptAllowsExactTuplesThenDropsOtherOverlayPorts(t *testing.T) {
	rules := []Rule{
		{
			ResourceID: "udp-resource", Source: netip.MustParseAddr("fd48:5542:4e45::3"),
			Destination:     netip.MustParseAddr("fd48:5542:4e45::2"),
			DestinationPort: 5353, Protocol: "udp", ExpiresAt: time.Now().Add(time.Minute),
		},
		{
			ResourceID: "tcp-resource", Source: netip.MustParseAddr("100.96.0.3"),
			Destination:     netip.MustParseAddr("100.96.0.2"),
			DestinationPort: 9001, Protocol: "tcp", ExpiresAt: time.Now().Add(time.Minute),
		},
	}
	script := buildNFTScript("hubnet0", rules, false)
	for _, expected := range []string{
		`iifname "hubnet0" ip saddr 100.96.0.3 ip daddr 100.96.0.2 tcp dport 9001 accept`,
		`iifname "hubnet0" ip6 saddr fd48:5542:4e45::3 ip6 daddr fd48:5542:4e45::2 udp dport 5353 accept`,
		`iifname "hubnet0" ip daddr 100.96.0.0/11 meta l4proto { tcp, udp } drop`,
		`iifname "hubnet0" ip6 daddr fd48:5542:4e45::/48 meta l4proto { tcp, udp } drop`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("script missing %q:\n%s", expected, script)
		}
	}
	if strings.Index(script, "tcp dport 9001 accept") > strings.Index(script, "100.96.0.0/11") {
		t.Fatal("deny rule precedes exact allow")
	}
}

func TestLinuxBackendReplacementIsAtomicAndRevocationDeletesFlow(t *testing.T) {
	runner := &recordingRunner{}
	backend := &linuxBackend{
		interfaceName: "hubnet0", runner: runner, removed: make(map[string][]Rule),
	}
	rule := Rule{
		ResourceID: "resource-1", Source: netip.MustParseAddr("100.96.0.3"),
		Destination:     netip.MustParseAddr("100.96.0.2"),
		DestinationPort: 9001, Protocol: "tcp",
	}
	if err := backend.ReplaceRules([]Rule{rule}); err != nil {
		t.Fatal(err)
	}
	if err := backend.ReplaceRules(nil); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(runner.calls[1].stdin, "delete table inet hub_net\ntable inet hub_net") {
		t.Fatalf("replacement not one nft transaction: %q", runner.calls[1].stdin)
	}
	if err := backend.TerminateResource("resource-1"); err != nil {
		t.Fatal(err)
	}
	last := runner.calls[len(runner.calls)-1]
	got := strings.Join(last.args, " ")
	if last.name != "conntrack" || !strings.Contains(got, "-D -f ipv4 -p tcp -s 100.96.0.3 -d 100.96.0.2 --dport 9001") {
		t.Fatalf("flow deletion = %s %s", last.name, got)
	}
}
