package main

import (
	"context"
	"testing"

	"github.com/v57/hub-net-node/identity"
	"github.com/v57/hub-net/invitation"
	"github.com/v57/hub-net/membership"
)

func TestNextFreeInterface(t *testing.T) {
	cases := []struct {
		used []string
		want string
	}{
		{nil, "hubnet0"},
		{[]string{"hubnet0"}, "hubnet1"},
		{[]string{"hubnet0", "hubnet1", "hubnet2"}, "hubnet3"},
		{[]string{"hubnet1", "hubnet0"}, "hubnet2"},
		{[]string{"hubnet0", "hubnet2"}, "hubnet1"},
	}
	for _, test := range cases {
		if got := nextFreeInterface(test.used); got != test.want {
			t.Errorf("nextFreeInterface(%v) = %q, want %q", test.used, got, test.want)
		}
	}
}

func TestOverlaySplit(t *testing.T) {
	addresses := []string{"100.96.0.2", "fd48:5542:4e45::2"}
	if got := overlayIPv4(addresses); got != "100.96.0.2" {
		t.Errorf("overlayIPv4 = %q", got)
	}
	if got := overlayIPv6(addresses); got != "fd48:5542:4e45::2" {
		t.Errorf("overlayIPv6 = %q", got)
	}
	if got := overlayIPv4([]string{}); got != "" {
		t.Errorf("overlayIPv4 empty = %q", got)
	}
}

func TestParseIdentityBlob(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := id.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseIdentityBlob(encoded)
	if err != nil {
		t.Fatalf("parseIdentityBlob: %v", err)
	}
	key, err := parsed.PublicKeyBase64()
	if err != nil {
		t.Fatal(err)
	}
	wantKey, _ := id.PublicKeyBase64()
	if key != wantKey {
		t.Errorf("parsed key = %q, want %q", key, wantKey)
	}
}

func TestStagedJoinIdentityReused(t *testing.T) {
	store, err := invitation.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := stagedJoinIdentity(ctx, store, "transaction-1")
	if err != nil {
		t.Fatalf("stagedJoinIdentity: %v", err)
	}
	again, err := stagedJoinIdentity(ctx, store, "transaction-1")
	if err != nil {
		t.Fatalf("stagedJoinIdentity retry: %v", err)
	}
	if first.Key != again.Key || first.WireGuardKey != again.WireGuardKey {
		t.Error("retry rotated the staged identity")
	}
	other, err := stagedJoinIdentity(ctx, store, "transaction-2")
	if err != nil {
		t.Fatalf("stagedJoinIdentity other: %v", err)
	}
	if other.Key == first.Key {
		t.Error("distinct transactions share an identity")
	}
}

func TestJoinRecordShape(t *testing.T) {
	root := t.TempDir()
	store, err := membership.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	result := invitation.JoinResult{
		HubProHost:       "100.96.0.1",
		HubNetworkID:     "net-id",
		HubName:          "My Hub",
		OverlayAddresses: []string{"100.96.0.2", "fd48:5542:4e45::2"},
	}
	record, err := joinRecord(store, "replay-id", result, "https://node.example.com/node")
	if err != nil {
		t.Fatalf("joinRecord: %v", err)
	}
	if record.ID != "replay-id" {
		t.Errorf("record.ID = %q", record.ID)
	}
	if record.Alias != "my-hub" {
		t.Errorf("record.Alias = %q", record.Alias)
	}
	if record.InterfaceName != "hubnet0" {
		t.Errorf("record.InterfaceName = %q", record.InterfaceName)
	}
	if record.NetworkID != "net-id" || record.CanonicalIPv4 != "100.96.0.2" || record.CanonicalIPv6 != "fd48:5542:4e45::2" {
		t.Errorf("record fields: %+v", record)
	}
	if string(record.HubAddress) != `"ws://100.96.0.1:1997"` {
		t.Errorf("record.HubAddress = %s", record.HubAddress)
	}
	if record.NodeURL != "https://node.example.com/node" {
		t.Errorf("record.NodeURL = %q", record.NodeURL)
	}
}
