//go:build linux

package enforcement

import (
	"bytes"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const nftTable = "hub_net"

type commandRunner interface {
	run(name string, args []string, stdin string) error
}

type execRunner struct{}

func (execRunner) run(name string, args []string, stdin string) error {
	command := exec.Command(name, args...)
	command.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// linuxBackend uses one owned nftables table. Each replacement is one nft
// transaction, so readers see either the previous complete ruleset or the new
// complete ruleset. conntrack deletes terminate established flows on immediate
// generation revocation.
type linuxBackend struct {
	mu            sync.Mutex
	interfaceName string
	runner        commandRunner
	installed     bool
	rules         []Rule
	removed       map[string][]Rule
}

func newPlatformBackend(interfaceName string) (Backend, error) {
	backend := &linuxBackend{
		interfaceName: interfaceName,
		runner:        execRunner{},
		removed:       make(map[string][]Rule),
	}
	if err := backend.runner.run("nft", []string{"--version"}, ""); err != nil {
		return nil, fmt.Errorf("enforcement: nftables unavailable: %w", err)
	}
	if err := backend.runner.run("conntrack", []string{"-V"}, ""); err != nil {
		return nil, fmt.Errorf("enforcement: conntrack unavailable: %w", err)
	}
	return backend, nil
}

func (b *linuxBackend) ReplaceRules(rules []Rule) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	script := buildNFTScript(b.interfaceName, rules, b.installed)
	if err := b.runner.run("nft", []string{"-f", "-"}, script); err != nil {
		return err
	}
	nextKeys := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		nextKeys[ruleKey(rule)] = struct{}{}
	}
	for _, rule := range b.rules {
		if _, retained := nextKeys[ruleKey(rule)]; !retained {
			b.removed[rule.ResourceID] = append(b.removed[rule.ResourceID], rule)
		}
	}
	b.rules = append([]Rule(nil), rules...)
	b.installed = true
	return nil
}

func (b *linuxBackend) TerminateResource(resourceID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	rules := b.removed[resourceID]
	delete(b.removed, resourceID)
	for _, rule := range rules {
		familyFlag := "-f"
		family := "ipv4"
		if rule.Source.Is6() {
			family = "ipv6"
		}
		args := []string{
			"-D", familyFlag, family,
			"-p", rule.Protocol,
			"-s", rule.Source.String(),
			"-d", rule.Destination.String(),
			"--dport", strconv.Itoa(int(rule.DestinationPort)),
		}
		if err := b.runner.run("conntrack", args, ""); err != nil {
			return err
		}
	}
	return nil
}

func buildNFTScript(interfaceName string, rules []Rule, replace bool) string {
	var output strings.Builder
	if replace {
		output.WriteString("delete table inet " + nftTable + "\n")
	}
	output.WriteString("table inet " + nftTable + " {\n")
	output.WriteString(" chain input {\n")
	output.WriteString("  type filter hook input priority filter; policy accept;\n")
	// Replies to connections this host opened. Revocation deletes conntrack
	// entries (TerminateResource), so revoked inbound flows do not survive.
	fmt.Fprintf(&output, "  iifname %q ct state established,related accept\n", interfaceName)

	sorted := append([]Rule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return ruleKey(sorted[i]) < ruleKey(sorted[j]) })
	for _, rule := range sorted {
		family := "ip"
		if rule.Destination.Is6() {
			family = "ip6"
		}
		if !rule.Source.IsValid() {
			fmt.Fprintf(
				&output,
				"  iifname %q %s daddr %s %s dport %d accept comment %q\n",
				interfaceName, family, rule.Destination,
				rule.Protocol, rule.DestinationPort, rule.ResourceID,
			)
			continue
		}
		fmt.Fprintf(
			&output,
			"  iifname %q %s saddr %s %s daddr %s %s dport %d accept comment %q\n",
			interfaceName, family, rule.Source, family, rule.Destination,
			rule.Protocol, rule.DestinationPort, rule.ResourceID,
		)
	}
	fmt.Fprintf(&output, "  iifname %q ip daddr 100.96.0.0/11 meta l4proto { tcp, udp } drop\n", interfaceName)
	fmt.Fprintf(&output, "  iifname %q ip6 daddr fd48:5542:4e45::/48 meta l4proto { tcp, udp } drop\n", interfaceName)
	output.WriteString(" }\n}\n")
	return output.String()
}

var _ Backend = (*linuxBackend)(nil)
