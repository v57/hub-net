package dnsresolver

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestViewSetIsolatesDuplicateSharesAndTranslatesAnswers(t *testing.T) {
	resolver := New()
	views, err := NewViewSet(resolver)
	if err != nil {
		t.Fatal(err)
	}
	authority := "files.v1-provider.hub.invalid"
	records := map[string]Lookup{
		authority: {
			ResourceID: "files",
			Addresses: []net.IP{
				net.ParseIP("100.96.1.7"),
				net.ParseIP("fd48:5542:4e45::107"),
			},
		},
	}
	if err := views.Replace("home", records,
		netip.MustParsePrefix("10.0.0.0/11"),
		netip.MustParsePrefix("fd80::/48")); err != nil {
		t.Fatal(err)
	}
	if err := views.Replace("work", records,
		netip.MustParsePrefix("10.32.0.0/11"),
		netip.MustParsePrefix("fd80:0:1::/48")); err != nil {
		t.Fatal(err)
	}
	resolver.Activate()

	home, err := resolver.Lookup("files.v1-provider.home.hub.invalid")
	if err != nil {
		t.Fatal(err)
	}
	work, err := resolver.Lookup("files.v1-provider.work.hub.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if got := home.Addresses[0].String(); got != "10.0.1.7" {
		t.Fatalf("home IPv4 = %s", got)
	}
	if got := work.Addresses[0].String(); got != "10.32.1.7" {
		t.Fatalf("work IPv4 = %s", got)
	}
	if got := home.Addresses[1].String(); got != "fd80::107" {
		t.Fatalf("home IPv6 = %s", got)
	}
	if got := work.Addresses[1].String(); got != "fd80:0:1::107" {
		t.Fatalf("work IPv6 = %s", got)
	}
	if _, err := resolver.Lookup(authority); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("unqualified lookup error = %v", err)
	}
}

func TestViewSetReplacementAndRemovalStayScoped(t *testing.T) {
	resolver := New()
	views, _ := NewViewSet(resolver)
	v4 := netip.MustParsePrefix("10.0.0.0/11")
	v6 := netip.MustParsePrefix("fd80::/48")
	record := func(id, address string) map[string]Lookup {
		return map[string]Lookup{"api.v1-provider.hub.invalid": {
			ResourceID: id, Addresses: []net.IP{net.ParseIP(address)},
		}}
	}
	if err := views.Replace("one", record("one", "100.96.0.1"), v4, v6); err != nil {
		t.Fatal(err)
	}
	if err := views.Replace("two", record("two", "100.96.0.2"),
		netip.MustParsePrefix("10.32.0.0/11"), netip.MustParsePrefix("fd80:0:1::/48")); err != nil {
		t.Fatal(err)
	}
	if err := views.Replace("one", map[string]Lookup{}, v4, v6); err != nil {
		t.Fatal(err)
	}
	resolver.Activate()
	if _, err := resolver.Lookup("api.v1-provider.one.hub.invalid"); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("removed record error = %v", err)
	}
	if _, err := resolver.Lookup("api.v1-provider.two.hub.invalid"); err != nil {
		t.Fatalf("sibling lookup: %v", err)
	}
	if err := views.Remove("two"); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Lookup("api.v1-provider.two.hub.invalid"); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("removed view error = %v", err)
	}
}

func TestViewSetRejectsNamespaceAndAddressEscapeWithoutMutation(t *testing.T) {
	resolver := New()
	views, _ := NewViewSet(resolver)
	v4 := netip.MustParsePrefix("10.0.0.0/11")
	v6 := netip.MustParsePrefix("fd80::/48")
	good := map[string]Lookup{"api.v1-provider.hub.invalid": {
		ResourceID: "good", Addresses: []net.IP{net.ParseIP("100.96.0.9")},
	}}
	if err := views.Replace("home", good, v4, v6); err != nil {
		t.Fatal(err)
	}
	bad := map[string]Lookup{"api.v1-provider.hub.invalid": {
		ResourceID: "bad", Addresses: []net.IP{net.ParseIP("192.0.2.1")},
	}}
	if err := views.Replace("home", bad, v4, v6); err == nil {
		t.Fatal("accepted non-overlay address")
	}
	resolver.Activate()
	got, err := resolver.Lookup("api.v1-provider.home.hub.invalid")
	if err != nil || got.ResourceID != "good" {
		t.Fatalf("failed update mutated view: got=%+v err=%v", got, err)
	}
	if _, err := Qualify("api.v1-provider.hub.invalid", "bad.alias"); err == nil {
		t.Fatal("accepted alias namespace escape")
	}
}
