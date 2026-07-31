//go:build linux

package translation

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var linuxInterfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

const linuxNFTTable = "hub_net_translation"

type linuxRunner interface {
	Run(name string, args []string, stdin string) ([]byte, error)
}

type commandRunner struct{}

func (commandRunner) Run(name string, args []string, stdin string) ([]byte, error) {
	command := exec.Command(name, args...)
	command.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return output, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return output, nil
}

type linuxBackend struct {
	runner   linuxRunner
	mu       sync.Mutex
	rpFilter map[string]string
	globalRP string
	active   map[string]Allocation
}

func newPlatformBackend() (Backend, error) {
	backend := &linuxBackend{runner: commandRunner{}, rpFilter: make(map[string]string), active: make(map[string]Allocation)}
	for _, command := range []string{"ip", "nft"} {
		if _, err := backend.runner.Run(command, []string{"--version"}, ""); err != nil {
			return nil, fmt.Errorf("translation: %s unavailable: %w", command, err)
		}
	}
	return backend, nil
}

type routeJSON struct {
	Destination string `json:"dst"`
}

func (b *linuxBackend) Routes() ([]netip.Prefix, error) {
	var routes []netip.Prefix
	for _, family := range [][]string{{"-4"}, {"-6"}} {
		args := append(family, "-json", "route", "show", "table", "all")
		output, err := b.runner.Run("ip", args, "")
		if err != nil {
			return nil, err
		}
		var entries []routeJSON
		if err := json.Unmarshal(output, &entries); err != nil {
			return nil, fmt.Errorf("translation: decode routes: %w", err)
		}
		for _, entry := range entries {
			if entry.Destination == "" || entry.Destination == "default" {
				continue
			}
			prefix, err := netip.ParsePrefix(entry.Destination)
			if err == nil {
				routes = append(routes, prefix.Masked())
			}
		}
	}
	return routes, nil
}

func (b *linuxBackend) Install(interfaceName string, allocation Allocation) error {
	if !linuxInterfaceName.MatchString(interfaceName) {
		return errors.New("translation: invalid Linux interface name")
	}
	if _, err := parseAllocation(allocation.IPv4.String(), allocation.IPv6.String()); err != nil {
		return err
	}
	// Recover stale state left by process or machine interruption before
	// installing the persisted allocation again.
	if err := b.Remove(interfaceName, allocation); err != nil {
		return fmt.Errorf("translation: clean stale state: %w", err)
	}
	if err := b.disableReversePathFilter(interfaceName); err != nil {
		return err
	}
	table, mark, priority, _ := linuxIdentifiers(interfaceName)
	commands := []struct {
		args []string
	}{
		{[]string{"-4", "route", "replace", allocation.IPv4.String(), "dev", interfaceName}},
		{[]string{"-6", "route", "replace", allocation.IPv6.String(), "dev", interfaceName}},
		{[]string{"-4", "route", "replace", CanonicalIPv4.String(), "dev", interfaceName, "table", table}},
		{[]string{"-4", "route", "replace", allocation.IPv4.String(), "dev", interfaceName, "table", table}},
		{[]string{"-6", "route", "replace", CanonicalIPv6.String(), "dev", interfaceName, "table", table}},
		{[]string{"-6", "route", "replace", allocation.IPv6.String(), "dev", interfaceName, "table", table}},
		{[]string{"-4", "rule", "add", "fwmark", mark, "lookup", table, "priority", priority}},
		{[]string{"-6", "rule", "add", "fwmark", mark, "lookup", table, "priority", priority}},
	}
	for _, command := range commands {
		if _, err := b.runner.Run("ip", command.args, ""); err != nil {
			return err
		}
	}
	b.mu.Lock()
	replace := len(b.active) > 0
	b.active[interfaceName] = allocation
	script := buildLinuxNFTScript(b.active, replace)
	b.mu.Unlock()
	if _, err := b.runner.Run("nft", []string{"-f", "-"}, script); err != nil {
		return err
	}
	return nil
}

func (b *linuxBackend) Remove(interfaceName string, allocation Allocation) error {
	if !linuxInterfaceName.MatchString(interfaceName) {
		return errors.New("translation: invalid Linux interface name")
	}
	table, mark, priority, _ := linuxIdentifiers(interfaceName)
	commands := []struct {
		name string
		args []string
	}{
		{"ip", []string{"-4", "rule", "del", "fwmark", mark, "lookup", table, "priority", priority}},
		{"ip", []string{"-6", "rule", "del", "fwmark", mark, "lookup", table, "priority", priority}},
		{"ip", []string{"-4", "route", "del", allocation.IPv4.String(), "dev", interfaceName}},
		{"ip", []string{"-6", "route", "del", allocation.IPv6.String(), "dev", interfaceName}},
		{"ip", []string{"-4", "route", "flush", "table", table}},
		{"ip", []string{"-6", "route", "flush", "table", table}},
	}
	var result error
	for _, command := range commands {
		if _, err := b.runner.Run(command.name, command.args, ""); err != nil && !isMissingLinuxState(err) {
			result = errors.Join(result, err)
		}
	}
	b.mu.Lock()
	_, wasActive := b.active[interfaceName]
	delete(b.active, interfaceName)
	remaining := len(b.active)
	var script string
	if wasActive && remaining > 0 {
		script = buildLinuxNFTScript(b.active, true)
	}
	b.mu.Unlock()
	if remaining == 0 {
		if _, err := b.runner.Run("nft", []string{"delete", "table", "inet", linuxNFTTable}, ""); err != nil &&
			!isMissingLinuxState(err) {
			result = errors.Join(result, err)
		}
	} else if script != "" {
		if _, err := b.runner.Run("nft", []string{"-f", "-"}, script); err != nil {
			result = errors.Join(result, err)
		}
	}
	if err := b.restoreReversePathFilter(interfaceName); err != nil {
		result = errors.Join(result, err)
	}
	return result
}

func (b *linuxBackend) disableReversePathFilter(interfaceName string) error {
	key := "net.ipv4.conf." + interfaceName + ".rp_filter"
	output, err := b.runner.Run("sysctl", []string{"-n", key}, "")
	if err != nil {
		return fmt.Errorf("translation: read reverse-path filter: %w", err)
	}
	previous := strings.TrimSpace(string(output))
	if previous == "" {
		// Recording runners need no synthetic sysctl state.
		previous = "0"
	}
	b.mu.Lock()
	first := len(b.rpFilter) == 0
	b.mu.Unlock()
	if first {
		globalOutput, globalErr := b.runner.Run("sysctl", []string{"-n", "net.ipv4.conf.all.rp_filter"}, "")
		if globalErr != nil {
			return fmt.Errorf("translation: read global reverse-path filter: %w", globalErr)
		}
		global := strings.TrimSpace(string(globalOutput))
		if global == "" {
			global = "0"
		}
		if _, globalErr = b.runner.Run("sysctl", []string{"-w", "net.ipv4.conf.all.rp_filter=0"}, ""); globalErr != nil {
			return fmt.Errorf("translation: relax global reverse-path filter: %w", globalErr)
		}
		b.mu.Lock()
		b.globalRP = global
		b.mu.Unlock()
	}
	b.mu.Lock()
	b.rpFilter[interfaceName] = previous
	b.mu.Unlock()
	if _, err := b.runner.Run("sysctl", []string{"-w", key + "=0"}, ""); err != nil {
		return fmt.Errorf("translation: disable interface reverse-path filter: %w", err)
	}
	return nil
}

func (b *linuxBackend) restoreReversePathFilter(interfaceName string) error {
	b.mu.Lock()
	previous, ok := b.rpFilter[interfaceName]
	delete(b.rpFilter, interfaceName)
	last := len(b.rpFilter) == 0
	global := b.globalRP
	if last {
		b.globalRP = ""
	}
	b.mu.Unlock()
	if !ok {
		return nil
	}
	key := "net.ipv4.conf." + interfaceName + ".rp_filter"
	if _, err := b.runner.Run("sysctl", []string{"-w", key + "=" + previous}, ""); err != nil &&
		!isMissingLinuxState(err) {
		return fmt.Errorf("translation: restore interface reverse-path filter: %w", err)
	}
	if last && global != "" {
		if _, err := b.runner.Run("sysctl", []string{"-w", "net.ipv4.conf.all.rp_filter=" + global}, ""); err != nil {
			return fmt.Errorf("translation: restore global reverse-path filter: %w", err)
		}
	}
	return nil
}

func linuxIdentifiers(interfaceName string) (table, mark, priority, nftTable string) {
	sum := sha256.Sum256([]byte(interfaceName))
	value := binary.BigEndian.Uint32(sum[:4])&0x3fffffff + 10000
	number := strconv.FormatUint(uint64(value), 10)
	priorityNumber := strconv.FormatUint(uint64(10000+value%20000), 10)
	return number, "0x" + strconv.FormatUint(uint64(value), 16), priorityNumber,
		linuxNFTTable
}

func buildLinuxNFTScript(active map[string]Allocation, replace bool) string {
	var output strings.Builder
	if replace {
		output.WriteString("delete table inet " + linuxNFTTable + "\n")
	}
	fmt.Fprintf(&output, `table inet %s {
 chain output {
  type nat hook output priority dstnat; policy accept;
`, linuxNFTTable)
	interfaces := make([]string, 0, len(active))
	for interfaceName := range active {
		interfaces = append(interfaces, interfaceName)
	}
	sort.Strings(interfaces)
	for _, interfaceName := range interfaces {
		allocation := active[interfaceName]
		_, mark, _, _ := linuxIdentifiers(interfaceName)
		fmt.Fprintf(&output,
			"  ip daddr %s counter meta mark set %s ct mark set meta mark dnat ip prefix to ip daddr map { %s : %s }\n",
			allocation.IPv4, mark, allocation.IPv4, CanonicalIPv4)
		fmt.Fprintf(&output,
			"  ip6 daddr %s counter meta mark set %s ct mark set meta mark dnat ip6 prefix to ip6 daddr map { %s : %s }\n",
			allocation.IPv6, mark, allocation.IPv6, CanonicalIPv6)
	}
	output.WriteString(` }
 chain mark_out {
  type route hook output priority mangle; policy accept;
  ct mark != 0 meta mark set ct mark
 }
 chain mark_in {
  type filter hook prerouting priority mangle; policy accept;
  ct mark != 0 meta mark set ct mark
 }
 chain prerouting {
  type nat hook prerouting priority dstnat; policy accept;
 }
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
`)
	for _, interfaceName := range interfaces {
		fmt.Fprintf(&output, "  oifname %q ip daddr %s masquerade\n", interfaceName, CanonicalIPv4)
		fmt.Fprintf(&output, "  oifname %q ip6 daddr %s masquerade\n", interfaceName, CanonicalIPv6)
	}
	output.WriteString(" }\n}\n")
	return output.String()
}

func isMissingLinuxState(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "no such file or directory") ||
		strings.Contains(text, "no such process") ||
		strings.Contains(text, "cannot find device") ||
		strings.Contains(text, "fib table does not exist")
}

var _ Backend = (*linuxBackend)(nil)
