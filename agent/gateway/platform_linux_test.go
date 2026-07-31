//go:build linux

package gateway

import (
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
