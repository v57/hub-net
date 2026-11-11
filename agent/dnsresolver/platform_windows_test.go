//go:build windows

package dnsresolver

import (
	"context"
	"net"
	"os"
	"regexp"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestNRPTListenAddress(t *testing.T) {
	installer := newPlatformInstaller("hubnet0").(*nrptInstaller)
	got := installer.ListenAddress("127.0.0.1:0")
	host, port, err := net.SplitHostPort(got)
	if err != nil || port != "53" {
		t.Fatalf("ListenAddress = %q", got)
	}
	if ip := net.ParseIP(host).To4(); ip == nil || ip[0] != 127 || ip[1] != 72 || ip[3] == 0 || ip[3] == 255 {
		t.Fatalf("ListenAddress host = %q", host)
	}
	if LoopbackFor("hubnet0") == LoopbackFor("hubnet1") {
		t.Fatal("two interfaces share a resolver address")
	}
	for _, explicit := range []string{"127.0.0.1:53", "127.0.0.1:5353", "0.0.0.0:0", "[::1]:0"} {
		if got := installer.ListenAddress(explicit); got != explicit {
			t.Errorf("ListenAddress(%q) = %q, want unchanged", explicit, got)
		}
	}
	if !regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\}$`).MatchString(installer.rule) {
		t.Fatalf("rule key %q", installer.rule)
	}
	if ruleKeyName("hubnet0") == ruleKeyName("hubnet1") {
		t.Fatal("two interfaces share a rule")
	}
}

func TestNRPTInstallRequiresPort53(t *testing.T) {
	installer := newPlatformInstaller("hubnet0")
	err := installer.Install(context.Background(), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353}, Suffix)
	if err == nil {
		t.Fatal("Install accepted a resolver NRPT can't reach")
	}
}

func privilegedDNS(t *testing.T) {
	t.Helper()
	if os.Getenv("HUBNET_DNS_TEST") != "1" {
		t.Skip("set HUBNET_DNS_TEST=1 in an elevated shell")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("not elevated")
	}
}

// TestNRPTEndToEnd starts the resolver as the agent does, checks the NRPT
// rule in the registry, resolves a hub name through the system resolver
// (DNS Client service, so NRPT applies), then checks Close removes the rule
// and the name stops resolving.
func TestNRPTEndToEnd(t *testing.T) {
	privilegedDNS(t)
	installer := newPlatformInstaller("hubnet-test-dns").(*nrptInstaller)
	resolver := New()
	const name = "web-test.home.hub.invalid"
	if err := resolver.Replace(map[string]Lookup{name: {ResourceID: "hnr1_test", Addresses: []net.IP{net.ParseIP("100.96.0.9")}}}); err != nil {
		t.Fatal(err)
	}
	resolver.Activate()
	server := &Server{Resolver: resolver, Installer: installer, Upstream: func(context.Context, []byte) ([]byte, error) {
		return nil, net.ErrClosed
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.StartUnconfigured(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer server.Close(context.Background())
	if err := server.Install(ctx); err != nil {
		t.Fatalf("install: %v", err)
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocalKey+`\`+installer.rule, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("rule key: %v", err)
	}
	names, _, _ := key.GetStringsValue("Name")
	servers, _, _ := key.GetStringValue("GenericDNSServers")
	key.Close()
	if len(names) != 1 || names[0] != ".hub.invalid" || servers != LoopbackFor("hubnet-test-dns").String() {
		t.Fatalf("rule Name=%v GenericDNSServers=%q", names, servers)
	}

	var addresses []string
	deadline := time.Now().Add(15 * time.Second)
	for {
		addresses, err = net.LookupHost(name)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil || len(addresses) == 0 || addresses[0] != "100.96.0.9" {
		t.Fatalf("system lookup of %s = %v, %v", name, addresses, err)
	}
	// Ordinary names don't go to the hub resolver: its upstream fails, so a
	// lookup that works went through the system's own servers.
	if _, err := net.LookupHost("localhost"); err != nil {
		t.Fatalf("localhost: %v", err)
	}

	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocalKey+`\`+installer.rule, registry.QUERY_VALUE); err == nil {
		t.Fatal("NRPT rule left after Close")
	}
	time.Sleep(time.Second)
	if addresses, err := net.LookupHost(name); err == nil {
		t.Fatalf("%s still resolves after Close: %v", name, addresses)
	}
}

// TestNRPTReinstallReplacesCrashLeftover writes the rule as a crashed agent
// would leave it, then checks Install overwrites it and Remove deletes it.
func TestNRPTReinstallReplacesCrashLeftover(t *testing.T) {
	privilegedDNS(t)
	installer := newPlatformInstaller("hubnet-test-dns2").(*nrptInstaller)
	if err := writeRule(nrptLocalKey, installer.rule, ".hub.invalid", "127.72.0.99"); err != nil {
		t.Fatal(err)
	}
	address := &net.UDPAddr{IP: LoopbackFor("hubnet-test-dns2").AsSlice(), Port: 53}
	if err := installer.Install(context.Background(), address, Suffix); err != nil {
		t.Fatal(err)
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocalKey+`\`+installer.rule, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	servers, _, _ := key.GetStringValue("GenericDNSServers")
	key.Close()
	if servers != address.IP.String() {
		t.Fatalf("GenericDNSServers = %q, want %s", servers, address.IP)
	}
	if err := installer.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := installer.Remove(context.Background()); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
	if _, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocalKey+`\`+installer.rule, registry.QUERY_VALUE); err == nil {
		t.Fatal("rule left after Remove")
	}
}
