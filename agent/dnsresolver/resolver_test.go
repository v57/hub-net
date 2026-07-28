package dnsresolver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func TestResolverLifecycleAndCanonicalLookup(t *testing.T) {
	resolver := New()
	authority := "s3-abcdefghijklmnop.v1-ponmlkjihgfedcba.hub.invalid"
	if err := resolver.Replace(map[string]Lookup{
		authority: {ResourceID: "hnr1_test", Addresses: []net.IP{net.ParseIP("100.96.0.8")}},
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if _, err := resolver.Lookup(authority); !errors.Is(err, ErrInactive) {
		t.Fatalf("inactive Lookup error = %v", err)
	}
	resolver.Activate()
	got, err := resolver.Lookup(authority + ".")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.ResourceID != "hnr1_test" || !got.Addresses[0].Equal(net.ParseIP("100.96.0.8")) {
		t.Fatalf("Lookup = %#v", got)
	}
	resolver.Deactivate()
	if _, err := resolver.Lookup(authority); !errors.Is(err, ErrInactive) {
		t.Fatalf("deactivated Lookup error = %v", err)
	}
}

func TestReservedSuffixBoundary(t *testing.T) {
	for _, name := range []string{"hub.invalid", "x.hub.invalid", "X.HUB.INVALID."} {
		if !IsHubName(name) {
			t.Errorf("IsHubName(%q) = false", name)
		}
	}
	for _, name := range []string{"hub.invalid.example", "nothub.invalid", "invalid", ""} {
		if IsHubName(name) {
			t.Errorf("IsHubName(%q) = true", name)
		}
	}
}

func TestServerAnswersHubAndForwardsOrdinaryDNS(t *testing.T) {
	resolver := New()
	authority := "s3-abcdefghijklmnop.v1-ponmlkjihgfedcba.hub.invalid"
	if err := resolver.Replace(map[string]Lookup{
		authority: {ResourceID: "hnr1_test", Addresses: []net.IP{net.ParseIP("100.96.0.8")}},
	}); err != nil {
		t.Fatal(err)
	}
	resolver.Activate()
	forwarded := false
	server := &Server{
		Resolver: resolver,
		Upstream: func(_ context.Context, packet []byte) ([]byte, error) {
			forwarded = true
			return append([]byte("upstream:"), packet...), nil
		},
	}

	response, err := server.Handle(context.Background(), query(7, authority, typeA))
	if err != nil {
		t.Fatalf("Handle Hub: %v", err)
	}
	if forwarded {
		t.Fatal("Hub query forwarded")
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 1 {
		t.Fatalf("answer count = %d", got)
	}
	if got := net.IP(response[len(response)-4:]).String(); got != "100.96.0.8" {
		t.Fatalf("answer = %s", got)
	}

	ordinary := query(8, "example.com", typeA)
	response, err = server.Handle(context.Background(), ordinary)
	if err != nil {
		t.Fatalf("Handle ordinary: %v", err)
	}
	if !forwarded || string(response) != "upstream:"+string(ordinary) {
		t.Fatal("ordinary DNS not preserved through upstream")
	}
}

func TestUnknownAndInactiveHubNamesReturnNXDOMAINWithoutForward(t *testing.T) {
	resolver := New()
	forwarded := false
	server := &Server{
		Resolver: resolver,
		Upstream: func(context.Context, []byte) ([]byte, error) {
			forwarded = true
			return nil, nil
		},
	}
	for _, name := range []string{"missing.hub.invalid", "hub.invalid"} {
		response, err := server.Handle(context.Background(), query(1, name, typeA))
		if err != nil {
			t.Fatalf("Handle: %v", err)
		}
		if response[3]&0x0f != 3 {
			t.Fatalf("%s rcode = %d", name, response[3]&0x0f)
		}
	}
	if forwarded {
		t.Fatal("reserved name forwarded")
	}
}

func TestServerStartCloseRemovesSplitDNS(t *testing.T) {
	resolver := New()
	installer := &MemoryInstaller{}
	server := &Server{Resolver: resolver, Installer: installer}
	if err := server.Start(context.Background(), "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !installer.Installed || installer.Suffix != Suffix {
		t.Fatalf("installer = %#v", installer)
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if installer.Installed {
		t.Fatal("split DNS remains installed")
	}
}

func TestReplaceRejectsNamespaceEscape(t *testing.T) {
	resolver := New()
	err := resolver.Replace(map[string]Lookup{
		"hub.invalid.example": {ResourceID: "hnr1_test", Addresses: []net.IP{net.ParseIP("100.96.0.8")}},
	})
	if err == nil {
		t.Fatal("Replace accepted non-Hub authority")
	}
}

func query(id uint16, name string, qtype uint16) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	for _, label := range split(name) {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0)
	packet = binary.BigEndian.AppendUint16(packet, qtype)
	packet = binary.BigEndian.AppendUint16(packet, classIN)
	return packet
}

func split(name string) []string {
	var result []string
	start := 0
	for index := range name {
		if name[index] == '.' {
			result = append(result, name[start:index])
			start = index + 1
		}
	}
	return append(result, name[start:])
}
