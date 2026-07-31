//go:build linux

package translation

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type linuxCall struct {
	name  string
	args  []string
	stdin string
}

type recordingLinuxRunner struct {
	calls      []linuxCall
	ipv4Routes string
	ipv6Routes string
	failMatch  string
}

func (r *recordingLinuxRunner) Run(name string, args []string, stdin string) ([]byte, error) {
	r.calls = append(r.calls, linuxCall{name: name, args: append([]string(nil), args...), stdin: stdin})
	joined := name + " " + strings.Join(args, " ")
	if r.failMatch != "" && strings.Contains(joined, r.failMatch) {
		return nil, errors.New("injected failure")
	}
	if strings.Contains(joined, "-4 -json route") {
		return []byte(r.ipv4Routes), nil
	}
	if strings.Contains(joined, "-6 -json route") {
		return []byte(r.ipv6Routes), nil
	}
	return nil, nil
}

func TestLinuxRouteProbeIncludesAllNonDefaultRoutes(t *testing.T) {
	runner := &recordingLinuxRunner{
		ipv4Routes: `[{"dst":"default"},{"dst":"10.32.0.0/11"},{"dst":"192.0.2.0/24"}]`,
		ipv6Routes: `[{"dst":"default"},{"dst":"fd80:1::/48"}]`,
	}
	backend := &linuxBackend{runner: runner, rpFilter: make(map[string]string), active: make(map[string]Allocation)}
	routes, err := backend.Routes()
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.32.0.0/11"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("fd80:1::/48"),
	}
	if len(routes) != len(want) {
		t.Fatalf("routes = %+v", routes)
	}
	for i := range want {
		if routes[i] != want[i] {
			t.Fatalf("routes[%d] = %s, want %s", i, routes[i], want[i])
		}
	}
}

func TestLinuxInstallBuildsPrefixNATAndPolicyRoutes(t *testing.T) {
	runner := &recordingLinuxRunner{}
	backend := &linuxBackend{runner: runner, rpFilter: make(map[string]string), active: make(map[string]Allocation)}
	allocation := Allocation{
		IPv4: netip.MustParsePrefix("10.32.0.0/11"),
		IPv6: netip.MustParsePrefix("fd80:1::/48"),
	}
	if err := backend.Install("hub12345678", allocation); err != nil {
		t.Fatal(err)
	}
	var nftScript string
	var commands []string
	for _, call := range runner.calls {
		commands = append(commands, call.name+" "+strings.Join(call.args, " "))
		if call.name == "nft" && len(call.args) == 2 && call.args[0] == "-f" {
			nftScript = call.stdin
		}
	}
	for _, want := range []string{
		"ip daddr 10.32.0.0/11 counter",
		"dnat ip prefix to ip daddr map { 10.32.0.0/11 : 100.96.0.0/11 }",
		"ip6 daddr fd80:1::/48 counter",
		"dnat ip6 prefix to ip6 daddr map { fd80:1::/48 : fd48:5542:4e45::/48 }",
		"ct mark set meta mark",
		"ct mark != 0 meta mark set ct mark",
		"type route hook output priority mangle",
		"type nat hook prerouting",
		"type nat hook postrouting",
		`oifname "hub12345678" ip daddr 100.96.0.0/11 masquerade`,
		`oifname "hub12345678" ip6 daddr fd48:5542:4e45::/48 masquerade`,
	} {
		if !strings.Contains(nftScript, want) {
			t.Fatalf("nft script missing %q:\n%s", want, nftScript)
		}
	}
	joined := strings.Join(commands, "\n")
	for _, want := range []string{
		"ip -4 route replace 10.32.0.0/11 dev hub12345678",
		"ip -6 route replace fd80:1::/48 dev hub12345678",
		"ip -4 route replace 100.96.0.0/11 dev hub12345678 table ",
		"ip -4 route replace 10.32.0.0/11 dev hub12345678 table ",
		"ip -6 route replace fd48:5542:4e45::/48 dev hub12345678 table ",
		"ip -6 route replace fd80:1::/48 dev hub12345678 table ",
		"ip -4 rule add fwmark 0x",
		"ip -6 rule add fwmark 0x",
		"sysctl -w net.ipv4.conf.hub12345678.rp_filter=0",
		"sysctl -w net.ipv4.conf.all.rp_filter=0",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("commands missing %q:\n%s", want, joined)
		}
	}
}

func TestLinuxInstallRejectsBadInterfaceAndCleanupIsScoped(t *testing.T) {
	backend := &linuxBackend{runner: &recordingLinuxRunner{}, rpFilter: make(map[string]string), active: make(map[string]Allocation)}
	allocation := Allocation{
		IPv4: netip.MustParsePrefix("10.32.0.0/11"),
		IPv6: netip.MustParsePrefix("fd80:1::/48"),
	}
	if err := backend.Install("bad interface", allocation); err == nil {
		t.Fatal("bad interface accepted")
	}
	runner := &recordingLinuxRunner{}
	shared := &linuxBackend{runner: runner, rpFilter: make(map[string]string), active: make(map[string]Allocation)}
	second := Allocation{
		IPv4: netip.MustParsePrefix("10.64.0.0/11"),
		IPv6: netip.MustParsePrefix("fd80:2::/48"),
	}
	if err := shared.Install("hub11111111", allocation); err != nil {
		t.Fatal(err)
	}
	if err := shared.Install("hub22222222", second); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	if err := shared.Remove("hub11111111", allocation); err != nil {
		t.Fatal(err)
	}
	commands := callsText(runner.calls)
	if !strings.Contains(commands, `oifname "hub22222222"`) ||
		strings.Contains(commands, `oifname "hub11111111"`) {
		t.Fatalf("shared table did not preserve only sibling:\n%s", commands)
	}
	if !strings.Contains(commands, "route del 10.32.0.0/11 dev hub11111111") ||
		strings.Contains(commands, "route del 10.64.0.0/11 dev hub22222222") {
		t.Fatalf("cleanup crossed route ownership:\n%s", commands)
	}
}

func callsText(calls []linuxCall) string {
	var values []string
	for _, call := range calls {
		values = append(values, call.name+" "+strings.Join(call.args, " ")+"\n"+call.stdin)
	}
	return strings.Join(values, "\n")
}

func TestLinuxPrivilegedOverlappingHubLifecycle(t *testing.T) {
	if os.Getenv("HUB_NET_PRIVILEGED") == "" || os.Geteuid() != 0 {
		t.Skip("set HUB_NET_PRIVILEGED=1 and run as root")
	}
	backend := &linuxBackend{runner: commandRunner{}, rpFilter: make(map[string]string), active: make(map[string]Allocation)}
	type endpoint struct {
		namespace  string
		hostIf     string
		peerIf     string
		allocation Allocation
	}
	endpoints := []endpoint{
		{"hn833a", "hub833a", "peer833a", Allocation{
			IPv4: netip.MustParsePrefix("10.32.0.0/11"),
			IPv6: netip.MustParsePrefix("fd80:1::/48"),
		}},
		{"hn833b", "hub833b", "peer833b", Allocation{
			IPv4: netip.MustParsePrefix("10.64.0.0/11"),
			IPv6: netip.MustParsePrefix("fd80:2::/48"),
		}},
	}
	var servers []*exec.Cmd
	cleanup := func() {
		for _, server := range servers {
			if server.Process != nil {
				_ = server.Process.Kill()
				_, _ = server.Process.Wait()
			}
		}
		for _, endpoint := range endpoints {
			_ = backend.Remove(endpoint.hostIf, endpoint.allocation)
			_ = exec.Command("ip", "link", "delete", endpoint.hostIf).Run()
			_ = exec.Command("ip", "netns", "delete", endpoint.namespace).Run()
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	for _, endpoint := range endpoints {
		runLinuxTestCommand(t, "ip", "netns", "add", endpoint.namespace)
		runLinuxTestCommand(t, "ip", "link", "add", endpoint.hostIf, "type", "veth", "peer", "name", endpoint.peerIf)
		runLinuxTestCommand(t, "ip", "link", "set", endpoint.peerIf, "netns", endpoint.namespace)
		runLinuxTestCommand(t, "ip", "addr", "add", "100.96.0.1/32", "dev", endpoint.hostIf)
		runLinuxTestCommand(t, "ip", "-6", "addr", "add", "fd48:5542:4e45::1/128",
			"dev", endpoint.hostIf, "nodad")
		runLinuxTestCommand(t, "ip", "link", "set", endpoint.hostIf, "up")
		runLinuxTestCommand(t, "ip", "netns", "exec", endpoint.namespace,
			"ip", "addr", "add", "100.96.0.2/32", "dev", endpoint.peerIf)
		runLinuxTestCommand(t, "ip", "netns", "exec", endpoint.namespace,
			"ip", "-6", "addr", "add", "fd48:5542:4e45::2/128",
			"dev", endpoint.peerIf, "nodad")
		runLinuxTestCommand(t, "ip", "netns", "exec", endpoint.namespace,
			"ip", "link", "set", endpoint.peerIf, "up")
		runLinuxTestCommand(t, "ip", "netns", "exec", endpoint.namespace,
			"ip", "link", "set", "lo", "up")
		runLinuxTestCommand(t, "ip", "netns", "exec", endpoint.namespace,
			"ip", "route", "add", "100.96.0.1/32", "dev", endpoint.peerIf)
		runLinuxTestCommand(t, "ip", "netns", "exec", endpoint.namespace,
			"ip", "-6", "route", "add", "fd48:5542:4e45::1/128", "dev", endpoint.peerIf)
		peerMAC := strings.TrimSpace(runLinuxTestCommandOutput(t, "ip", "netns", "exec", endpoint.namespace,
			"cat", "/sys/class/net/"+endpoint.peerIf+"/address"))
		hostMAC := strings.TrimSpace(runLinuxTestCommandOutput(t, "cat", "/sys/class/net/"+endpoint.hostIf+"/address"))
		runLinuxTestCommand(t, "ip", "neigh", "replace", "100.96.0.2", "lladdr", peerMAC,
			"nud", "permanent", "dev", endpoint.hostIf)
		runLinuxTestCommand(t, "ip", "netns", "exec", endpoint.namespace,
			"ip", "neigh", "replace", "100.96.0.1", "lladdr", hostMAC,
			"nud", "permanent", "dev", endpoint.peerIf)
		runLinuxTestCommand(t, "ip", "-6", "neigh", "replace", "fd48:5542:4e45::2",
			"lladdr", peerMAC, "nud", "permanent", "dev", endpoint.hostIf)
		runLinuxTestCommand(t, "ip", "netns", "exec", endpoint.namespace,
			"ip", "-6", "neigh", "replace", "fd48:5542:4e45::1",
			"lladdr", hostMAC, "nud", "permanent", "dev", endpoint.peerIf)
		if err := backend.Install(endpoint.hostIf, endpoint.allocation); err != nil {
			t.Fatalf("Install %s: %v", endpoint.hostIf, err)
		}
		server := exec.Command("ip", "netns", "exec", endpoint.namespace, "python3", "-c", `
import socket,sys
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("100.96.0.2",8080))
s.listen()
while True:
 c,_=s.accept()
 c.recv(4096)
 body=sys.argv[1].encode()
 c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body)
 c.close()
`, endpoint.namespace)
		if err := server.Start(); err != nil {
			t.Fatalf("start server %s: %v", endpoint.namespace, err)
		}
		servers = append(servers, server)
		server6 := exec.Command("ip", "netns", "exec", endpoint.namespace, "python3", "-c", `
import socket,sys
s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("fd48:5542:4e45::2",8081))
s.listen()
while True:
 c,_=s.accept()
 c.recv(4096)
 body=sys.argv[1].encode()
 c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body)
 c.close()
`, endpoint.namespace+"-v6")
		if err := server6.Start(); err != nil {
			t.Fatalf("start IPv6 server %s: %v", endpoint.namespace, err)
		}
		servers = append(servers, server6)
	}
	time.Sleep(100 * time.Millisecond)

	// Both translated destinations map to the same canonical peer address,
	// but marks and policy tables select different per-Hub interfaces.
	for index, destination := range []string{"10.32.0.2", "10.64.0.2"} {
		output, err := translatedHTTP(destination)
		if err != nil || strings.TrimSpace(string(output)) != endpoints[index].namespace {
			for _, endpoint := range endpoints {
				table, mark, _, nftTable := linuxIdentifiers(endpoint.hostIf)
				for _, diagnostic := range [][]string{
					{"ip", "-4", "rule", "show"},
					{"conntrack", "-L", "-o", "extended"},
					{"ip", "-4", "route", "show", "table", table},
					{"ip", "-4", "route", "get", "100.96.0.2", "mark", mark},
					{"nft", "list", "table", "inet", nftTable},
					{"ip", "-s", "link", "show", endpoint.hostIf},
					{"ip", "neigh", "show", "dev", endpoint.hostIf},
					{"ip", "netns", "exec", endpoint.namespace, "ip", "addr", "show"},
					{"ip", "netns", "exec", endpoint.namespace, "ip", "-s", "link", "show", endpoint.peerIf},
				} {
					got, _ := exec.Command(diagnostic[0], diagnostic[1:]...).CombinedOutput()
					t.Logf("%s: %s", strings.Join(diagnostic, " "), got)
				}
			}
			t.Fatalf("HTTP %s: %v: %s", destination, err, output)
		}
	}
	for index, destination := range []string{"fd80:1::2", "fd80:2::2"} {
		output, err := translatedHTTP6(destination)
		if err != nil || strings.TrimSpace(string(output)) != endpoints[index].namespace+"-v6" {
			t.Fatalf("IPv6 HTTP %s: %v: %s", destination, err, output)
		}
	}

	// Restart deterministically repairs stale rules/routes for one Hub.
	if err := backend.Install(endpoints[0].hostIf, endpoints[0].allocation); err != nil {
		t.Fatalf("restart install: %v", err)
	}
	if output, err := translatedHTTP("10.32.0.2"); err != nil || strings.TrimSpace(string(output)) != "hn833a" {
		t.Fatalf("restart request: %v: %s", err, output)
	}
	if output, err := translatedHTTP6("fd80:1::2"); err != nil || strings.TrimSpace(string(output)) != "hn833a-v6" {
		t.Fatalf("IPv6 restart request: %v: %s", err, output)
	}

	// Removing one Hub leaves sibling translation live.
	if err := backend.Remove(endpoints[0].hostIf, endpoints[0].allocation); err != nil {
		t.Fatalf("remove first: %v", err)
	}
	if output, err := translatedHTTP("10.64.0.2"); err != nil || strings.TrimSpace(string(output)) != "hn833b" {
		t.Fatalf("sibling request after remove: %v: %s", err, output)
	}
	if output, err := translatedHTTP6("fd80:2::2"); err != nil || strings.TrimSpace(string(output)) != "hn833b-v6" {
		t.Fatalf("IPv6 sibling request after remove: %v: %s", err, output)
	}
	if _, err := translatedHTTP("10.32.0.2"); err == nil {
		t.Fatal("removed translated destination still reachable")
	}
	if _, err := translatedHTTP6("fd80:1::2"); err == nil {
		t.Fatal("removed IPv6 translated destination still reachable")
	}
}

func translatedHTTP(address string) ([]byte, error) {
	return exec.Command("curl", "-sS", "--noproxy", "*", "--max-time", "2",
		"http://"+address+":8080/").CombinedOutput()
}

func translatedHTTP6(address string) ([]byte, error) {
	return exec.Command("curl", "-g", "-sS", "--noproxy", "*", "--max-time", "2",
		"http://["+address+"]:8081/").CombinedOutput()
}

func runLinuxTestCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	_ = runLinuxTestCommandOutput(t, name, args...)
}

func runLinuxTestCommandOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}
