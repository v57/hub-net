//go:build linux

package gateway

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRulesContainGatewayAndDropProtectedDestinations(t *testing.T) {
	value := rules(DefaultConfig("hubabc"), "hub_gw_hubabc")
	for _, expected := range []string{
		`chain input { type filter hook input priority -10; policy accept;`,
		`iifname "hubabc" icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept`,
		`iifname "hubabc" ip daddr 127.0.0.0/8 drop`,
		`iifname "hubabc" ip daddr 192.168.0.0/16 drop`,
		`iifname "hubabc" ip6 daddr fc00::/7 drop`,
		`iifname "hubabc" ip saddr 100.96.0.0/11 accept`,
		`iifname "hubabc" drop`,
		`masquerade`,
	} {
		if !strings.Contains(value, expected) {
			t.Fatalf("rules missing %q:\n%s", expected, value)
		}
	}
}

func TestRulesProtectManagementPortsOnInputAndForward(t *testing.T) {
	config := DefaultConfig("hubabc")
	config.ManagementPorts = []uint16{8443}
	value := rules(config, "hub_gw_hubabc")
	if got := strings.Count(value, `iifname "hubabc" meta l4proto { tcp, udp } th dport 8443 drop`); got != 2 {
		t.Fatalf("management rule count = %d, want input and forward rules:\n%s", got, value)
	}
}

// Turning the gateway on must not cut the host off its own Hub Network: the
// hub's answers (established) and the devices reaching this interface's own
// addresses pass before 100.64.0.0/10, which holds the overlay, is dropped.
func TestRulesKeepTheHostsOwnHubNetwork(t *testing.T) {
	config := DefaultConfig("hubabc")
	config.LocalAddresses = []netip.Addr{netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("fd48:5542:4e45::2")}
	value := rules(config, "hub_gw_hubabc")
	input := value[:strings.Index(value, "chain forward")]
	drop := strings.Index(input, `ip daddr 100.64.0.0/10 drop`)
	for _, expected := range []string{
		`iifname "hubabc" ct state established,related accept`,
		`iifname "hubabc" ip daddr 100.96.0.2 accept`,
		`iifname "hubabc" ip6 daddr fd48:5542:4e45::2 accept`,
	} {
		at := strings.Index(input, expected)
		if at < 0 || at > drop {
			t.Fatalf("input chain lacks %q before the protected drops:\n%s", expected, input)
		}
	}
	if strings.Contains(input, "100.96.0.0/11 accept") {
		t.Fatalf("input chain accepts the whole overlay, other Hubs' addresses included:\n%s", input)
	}
}
