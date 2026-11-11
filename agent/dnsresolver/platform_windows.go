//go:build windows

package dnsresolver

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// NRPT (Name Resolution Policy Table) rules, read by the DNS Client service.
// Local rules live under the service's parameters; when Group Policy sets
// NRPT rules the local ones are ignored, so the rule goes to the policy key
// too and policy is refreshed.
const (
	nrptLocalKey  = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptPolicyKey = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	// ConfigOptions: the rule names generic DNS servers.
	nrptGenericDNSServers = 0x8
	nrptVersion           = 2
)

var (
	dnsapi                    = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache = dnsapi.NewProc("DnsFlushResolverCache")
	userenv                   = windows.NewLazySystemDLL("userenv.dll")
	procRefreshPolicyEx       = userenv.NewProc("RefreshPolicyEx")
)

// nrptInstaller routes the reserved suffix to the agent's resolver with one
// NRPT rule per interface, keyed by a GUID derived from the interface name so
// a rule left by a crash is replaced (and removed) by the next start.
type nrptInstaller struct {
	interfaceName string
	localKey      string
	policyKey     string
	rule          string
}

func newPlatformInstaller(interfaceName string) Installer {
	return &nrptInstaller{
		interfaceName: interfaceName,
		localKey:      nrptLocalKey,
		policyKey:     nrptPolicyKey,
		rule:          ruleKeyName(interfaceName),
	}
}

func ruleKeyName(interfaceName string) string {
	sum := sha256.Sum256([]byte("hub-net nrpt " + interfaceName))
	sum[6] = sum[6]&0x0f | 0x50
	sum[8] = sum[8]&0x3f | 0x80
	return fmt.Sprintf("{%X-%X-%X-%X-%X}", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

// ListenAddress moves the default loopback resolver ("127.0.0.1:0") to port
// 53 of a loopback address of the interface's own, 127.72.x.y: NRPT names a
// server without a port, and each membership runs its own resolver.
func (i *nrptInstaller) ListenAddress(configured string) string {
	host, port, err := net.SplitHostPort(configured)
	if err != nil || port != "0" {
		return configured
	}
	if address, err := netip.ParseAddr(host); err != nil || !address.IsLoopback() || !address.Is4() {
		return configured
	}
	return net.JoinHostPort(LoopbackFor(i.interfaceName).String(), "53")
}

// LoopbackFor is the interface's resolver address in 127.72.0.0/16.
func LoopbackFor(interfaceName string) netip.Addr {
	hash := fnv.New32a()
	hash.Write([]byte(interfaceName))
	sum := hash.Sum32()
	last := byte(sum%254) + 1
	return netip.AddrFrom4([4]byte{127, 72, byte(sum >> 8), last})
}

func (i *nrptInstaller) Install(_ context.Context, address net.Addr, suffix string) error {
	udp, ok := address.(*net.UDPAddr)
	if !ok || udp.IP == nil {
		return fmt.Errorf("dnsresolver: invalid local DNS address %v", address)
	}
	if udp.Port != 53 {
		return fmt.Errorf("dnsresolver: NRPT needs the resolver on port 53, not %s", udp)
	}
	name := "." + strings.TrimPrefix(suffix, ".")
	if err := writeRule(i.localKey, i.rule, name, udp.IP.String()); err != nil {
		return err
	}
	policy := policyActive(i.policyKey)
	if policy {
		if err := writeRule(i.policyKey, i.rule, name, udp.IP.String()); err != nil {
			_ = deleteRule(i.localKey, i.rule)
			return err
		}
		refreshPolicy()
	}
	flushCache()
	return nil
}

func (i *nrptInstaller) Remove(context.Context) error {
	err := deleteRule(i.localKey, i.rule)
	policyErr := deleteRule(i.policyKey, i.rule)
	if policyErr == nil && policyActive(i.policyKey) {
		refreshPolicy()
	}
	flushCache()
	return errors.Join(err, policyErr)
}

func writeRule(base, rule, name, server string) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, base+`\`+rule, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("dnsresolver: NRPT rule %s: %w", base, err)
	}
	defer key.Close()
	return errors.Join(
		key.SetDWordValue("Version", nrptVersion),
		key.SetStringsValue("Name", []string{name}),
		key.SetStringValue("GenericDNSServers", server),
		key.SetDWordValue("ConfigOptions", nrptGenericDNSServers),
		key.SetStringValue("IPSECCARestriction", ""),
	)
}

func deleteRule(base, rule string) error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, base+`\`+rule)
	if err == nil || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	return fmt.Errorf("dnsresolver: remove NRPT rule %s: %w", base, err)
}

// policyActive reports whether Group Policy carries NRPT rules (other than
// ours), which hide the local ones.
func policyActive(base string) bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(-1)
	return err == nil && len(names) > 0
}

func refreshPolicy() {
	// RefreshPolicyEx(bMachine = TRUE, RP_FORCE)
	if procRefreshPolicyEx.Find() == nil {
		procRefreshPolicyEx.Call(1, 1)
	}
}

func flushCache() {
	if procDnsFlushResolverCache.Find() == nil {
		procDnsFlushResolverCache.Call()
	}
}
