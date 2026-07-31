//go:build linux

package gateway

import (
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLinuxPrivilegedGatewayContainmentAndRevocation(t *testing.T) {
	if os.Getenv("HUB_NET_PRIVILEGED") == "" || os.Geteuid() != 0 {
		t.Skip("set HUB_NET_PRIVILEGED=1 and run as root")
	}

	const (
		clientNS = "hn843-client"
		netNS    = "hn843-net"
		nodeNS   = "hn843-node"
		clientIf = "hn843in"
		wanIf    = "hn843wan"
		nodeIf   = "hn843node"
	)
	namespaces := []string{clientNS, netNS, nodeNS}
	links := []string{clientIf, wanIf, nodeIf, "hn843lan", "hn843other"}
	var servers []*exec.Cmd
	cleanup := func() {
		for _, server := range servers {
			if server.Process != nil {
				_ = server.Process.Kill()
				_, _ = server.Process.Wait()
			}
		}
		_ = exec.Command("nft", "delete", "table", "inet", tableName(clientIf)).Run()
		for _, link := range links {
			_ = exec.Command("ip", "link", "delete", link).Run()
		}
		for _, namespace := range namespaces {
			_ = exec.Command("ip", "netns", "delete", namespace).Run()
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	for _, namespace := range namespaces {
		gatewayCommand(t, "ip", "netns", "add", namespace)
		gatewayCommand(t, "ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up")
	}
	addVeth(t, clientIf, "hn843c", clientNS)
	addVeth(t, wanIf, "hn843n", netNS)
	addVeth(t, nodeIf, "hn843nd", nodeNS)

	address(t, "", clientIf, "100.96.0.1/24", "fd48:5542:4e45::1/64")
	address(t, clientNS, "hn843c", "100.96.0.2/24", "fd48:5542:4e45::2/64")
	address(t, "", wanIf, "198.51.100.1/24", "2001:db8:1::1/64")
	address(t, netNS, "hn843n", "198.51.100.2/24", "2001:db8:1::2/64")
	address(t, "", nodeIf, "203.0.113.1/24", "2001:db8:2::1/64")
	address(t, nodeNS, "hn843nd", "203.0.113.2/24", "2001:db8:2::2/64")

	for _, item := range []struct {
		name string
		v4   string
		v6   string
	}{
		{"hn843lan", "192.168.50.1/32", "fd00:843::1/128"},
		{"hn843other", "100.97.0.1/32", "fd48:5542:4e45:1::1/128"},
	} {
		gatewayCommand(t, "ip", "link", "add", item.name, "type", "dummy")
		address(t, "", item.name, item.v4, item.v6)
	}

	gatewayCommand(t, "ip", "netns", "exec", clientNS, "ip", "route", "add", "default", "via", "100.96.0.1")
	gatewayCommand(t, "ip", "netns", "exec", clientNS, "ip", "-6", "route", "add", "default", "via", "fd48:5542:4e45::1")
	// Return routes make failures diagnostic; DNS assertions below still prove
	// both families were masqueraded to the gateway's WAN addresses.
	gatewayCommand(t, "ip", "netns", "exec", netNS, "ip", "route", "add", "100.96.0.0/11", "via", "198.51.100.1")
	gatewayCommand(t, "ip", "netns", "exec", netNS, "ip", "-6", "route", "add", "fd48:5542:4e45::/48", "via", "2001:db8:1::1")
	// Force loopback probes onto gateway interface instead of client's local table.
	gatewayCommand(t, "ip", "netns", "exec", clientNS, "ip", "addr", "delete", "127.0.0.1/8", "dev", "lo")
	gatewayCommand(t, "ip", "netns", "exec", clientNS, "ip", "route", "add", "127.0.0.1/32", "via", "100.96.0.1")

	dnsServer := exec.Command("ip", "netns", "exec", netNS, "python3", "-c", `
import socket
for family,address in [(socket.AF_INET,"198.51.100.2"),(socket.AF_INET6,"2001:db8:1::2")]:
 s=socket.socket(family,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((address,53))
 if family == socket.AF_INET: s4=s
 else: s6=s
while True:
 import select
 for s in select.select([s4,s6],[],[])[0]:
  data,peer=s.recvfrom(512); s.sendto(("hn843-dns:"+peer[0]+":").encode()+data,peer)
`)
	if err := dnsServer.Start(); err != nil {
		t.Fatalf("start DNS server: %v", err)
	}
	servers = append(servers, dnsServer)

	managementServer := exec.Command("python3", "-c", `
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("198.51.100.1",8443)); s.listen()
while True:
 c,_=s.accept(); c.sendall(b"management"); c.close()
`)
	if err := managementServer.Start(); err != nil {
		t.Fatalf("start management server: %v", err)
	}
	servers = append(servers, managementServer)
	time.Sleep(100 * time.Millisecond)

	config := DefaultConfig(clientIf)
	config.ManagementPorts = []uint16{8443}
	config.ProtectedIPv4 = append(config.ProtectedIPv4, netip.MustParsePrefix("203.0.113.0/24"))
	config.ProtectedIPv6 = append(config.ProtectedIPv6, netip.MustParsePrefix("2001:db8:2::/64"))
	backend := &linuxBackend{runner: commandRunner{}}
	if err := backend.Enable(config); err != nil {
		t.Fatalf("enable gateway: %v", err)
	}
	t.Cleanup(func() { _ = backend.Disable() })

	ping(t, clientNS, "198.51.100.2", false, true)
	dnsProbe(t, clientNS, "198.51.100.2", "198.51.100.1", false, true)
	dnsProbe(t, clientNS, "2001:db8:1::2", "2001:db8:1::1", true, true)

	for _, target := range []struct {
		address string
		ipv6    bool
		label   string
	}{
		{"127.0.0.1", false, "loopback"},
		{"192.168.50.1", false, "LAN IPv4"},
		{"fd00:843::1", true, "LAN IPv6"},
		{"100.97.0.1", false, "other-Hub IPv4"},
		{"fd48:5542:4e45:1::1", true, "other-Hub IPv6"},
		{"203.0.113.2", false, "node IPv4"},
		{"2001:db8:2::2", true, "node IPv6"},
	} {
		if ping(t, clientNS, target.address, target.ipv6, false) {
			t.Fatalf("%s destination %s reachable", target.label, target.address)
		}
	}
	if gatewayExec(clientNS, "curl", "-sS", "--max-time", "1", "http://198.51.100.1:8443/") == nil {
		t.Fatal("gateway management port reachable")
	}

	nodePackets := interfaceRXPackets(t, nodeNS, "hn843nd")
	ping(t, clientNS, "198.51.100.2", false, true)
	dnsProbe(t, clientNS, "2001:db8:1::2", "2001:db8:1::1", true, true)
	if got := interfaceRXPackets(t, nodeNS, "hn843nd"); got != nodePackets {
		t.Fatalf("internet packets traversed rendezvous node: RX %d became %d", nodePackets, got)
	}

	if err := backend.Disable(); err != nil {
		t.Fatalf("disable gateway: %v", err)
	}
	ping(t, clientNS, "198.51.100.2", false, false)
	ping(t, clientNS, "2001:db8:1::2", true, false)
	if output, err := exec.Command("nft", "list", "table", "inet", tableName(clientIf)).CombinedOutput(); err == nil {
		t.Fatalf("gateway table survived revocation: %s", output)
	}
}

func addVeth(t *testing.T, host, peer, namespace string) {
	t.Helper()
	gatewayCommand(t, "ip", "link", "add", host, "type", "veth", "peer", "name", peer)
	gatewayCommand(t, "ip", "link", "set", peer, "netns", namespace)
}

func address(t *testing.T, namespace, device, ipv4, ipv6 string) {
	t.Helper()
	prefix := []string{}
	if namespace != "" {
		prefix = []string{"netns", "exec", namespace, "ip"}
	}
	gatewayCommand(t, "ip", append(prefix, "addr", "add", ipv4, "dev", device)...)
	gatewayCommand(t, "ip", append(prefix, "-6", "addr", "add", ipv6, "dev", device, "nodad")...)
	gatewayCommand(t, "ip", append(prefix, "link", "set", device, "up")...)
}

func ping(t *testing.T, namespace, target string, ipv6, required bool) bool {
	t.Helper()
	args := []string{"netns", "exec", namespace, "ping", "-c", "1", "-W", "1"}
	if ipv6 {
		args = append(args, "-6")
	}
	err := gatewayExec("", "ip", append(args, target)...)
	if required && err != nil {
		for _, command := range [][]string{
			{"ip", "-6", "route", "show"},
			{"ip", "netns", "exec", namespace, "ip", "-6", "route", "show"},
			{"nft", "list", "table", "inet", tableName("hn843in")},
			{"ip", "-s", "link", "show", "hn843in"},
			{"ip", "-s", "link", "show", "hn843wan"},
		} {
			output, _ := exec.Command(command[0], command[1:]...).CombinedOutput()
			t.Logf("%s: %s", strings.Join(command, " "), output)
		}
		t.Fatalf("ping %s: %v", target, err)
	}
	return err == nil
}

func dnsProbe(t *testing.T, namespace, target, expectedSource string, ipv6, required bool) bool {
	t.Helper()
	family := "socket.AF_INET"
	if ipv6 {
		family = "socket.AF_INET6"
	}
	script := `import socket,sys;s=socket.socket(` + family + `,socket.SOCK_DGRAM);s.settimeout(1);s.sendto(b"query",(sys.argv[1],53));got=s.recv(128);want=("hn843-dns:"+sys.argv[2]+":query").encode();print(got);assert got==want`
	args := []string{"netns", "exec", namespace, "python3", "-c", script, target, expectedSource}
	output, err := exec.Command("ip", args...).CombinedOutput()
	if required && err != nil {
		for _, command := range [][]string{
			{"conntrack", "-L", "-f", "ipv6", "-o", "extended"},
			{"ip", "netns", "exec", "hn843-net", "ip", "-6", "route", "show"},
			{"ip", "netns", "exec", "hn843-net", "ip", "-6", "neigh", "show"},
			{"sysctl", "net.ipv6.conf.all.forwarding"},
		} {
			diagnostic, _ := exec.Command(command[0], command[1:]...).CombinedOutput()
			t.Logf("%s: %s", strings.Join(command, " "), diagnostic)
		}
		t.Fatalf("DNS %s: %v: %s", target, err, output)
	}
	return err == nil
}

func interfaceRXPackets(t *testing.T, namespace, device string) uint64 {
	t.Helper()
	output := gatewayCommandOutput(t, "ip", "netns", "exec", namespace, "cat", "/sys/class/net/"+device+"/statistics/rx_packets")
	value, err := strconv.ParseUint(strings.TrimSpace(output), 10, 64)
	if err != nil {
		t.Fatalf("parse %s RX packets: %v", device, err)
	}
	return value
}

func gatewayExec(namespace, name string, args ...string) error {
	if namespace != "" {
		args = append([]string{"netns", "exec", namespace, name}, args...)
		name = "ip"
	}
	return exec.Command(name, args...).Run()
}

func gatewayCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	_ = gatewayCommandOutput(t, name, args...)
}

func gatewayCommandOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}
