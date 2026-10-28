package nodeclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/v57/hub-net-node/identity"
	network "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
)

func hubGrant(t *testing.T, a, b string) network.PeerLinkGrant {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(public)
	now := time.Now().UTC()
	grant := network.PeerLinkGrant{
		Version: network.WireVersion, GrantID: "grant", HubKey: base64.StdEncoding.EncodeToString(der),
		HubNetworkID: "network", Purpose: network.PeerLinkPurposeHub,
		A:     network.PeerLinkSide{Key: a, WireGuardKey: "wg-a", Member: a, Addresses: []string{"100.96.0.3"}},
		B:     network.PeerLinkSide{Key: b, WireGuardKey: "wg-b", Member: b, Addresses: []string{"100.96.0.2"}},
		AViaB: []string{"100.96.0.2/32"}, BViaA: []string{"100.96.0.3/32"},
		AToB: []network.PeerLinkPort{{Protocol: "tcp", Port: 1997}}, BToA: []network.PeerLinkPort{},
		IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	grant.Signature, err = network.SignEnvelope(network.PurposePeerLink, grant, private)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

type linkDevice struct {
	client *Client
	key    string
	pushes chan protocol.Envelope
}

func startLinkDevice(t *testing.T, ctx context.Context, address string) linkDevice {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pushes := make(chan protocol.Envelope, 16)
	client, err := New(Options{
		Endpoint: func() string { return address },
		Identity: id,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Links:    func(envelope protocol.Envelope) { pushes <- envelope },
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = client.Run(ctx) }()
	waitOnline(t, client)
	return linkDevice{client: client, key: serviceKey(t, id), pushes: pushes}
}

func (d linkDevice) next(t *testing.T, messageType protocol.MessageType) protocol.Envelope {
	t.Helper()
	for {
		select {
		case envelope := <-d.pushes:
			if envelope.Type == messageType {
				return envelope
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s", messageType)
		}
	}
}

func probeLink(t *testing.T, address, linkID, token string) {
	t.Helper()
	conn, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload, _ := json.Marshal(protocol.LinkUDPProbe{Version: network.WireVersion, LinkID: linkID, ProbeToken: token})
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 512)
	if _, err := conn.Read(buffer); err != nil {
		t.Fatalf("probe answer: %v", err)
	}
}

// A member opens a link to the hub's machine on its presence connection: the
// machine gets link.incoming, accepts, both probe and both get link.ready,
// with neither presence registration dropping on the way.
func TestClientsRunAPeerLinkThroughTheNode(t *testing.T) {
	address, cleanup := runNodeServer(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	member := startLinkDevice(t, ctx, address)
	machine := startLinkDevice(t, ctx, address)
	grant := hubGrant(t, member.key, machine.key)

	opened, err := member.client.OpenLink(ctx, grant)
	if err != nil {
		t.Fatalf("OpenLink: %v", err)
	}
	if opened.PeerKey != machine.key || opened.LinkID == "" {
		t.Fatalf("opened = %+v", opened)
	}
	incoming := machine.next(t, protocol.MessageLinkIncoming)
	if incoming.LinkID != opened.LinkID || incoming.PeerKey != member.key || incoming.Grant == nil {
		t.Fatalf("incoming = %+v", incoming)
	}
	if err := machine.client.SendLink(protocol.MessageLinkAccept, incoming.LinkID, nil); err != nil {
		t.Fatal(err)
	}
	if err := machine.client.SendLink(protocol.MessageLinkOffer, incoming.LinkID,
		[]network.LinkEndpoint{{Address: "192.168.1.2", Port: 51820}}); err != nil {
		t.Fatal(err)
	}
	probeLink(t, address, opened.LinkID, opened.ProbeToken)
	probeLink(t, address, incoming.LinkID, incoming.ProbeToken)
	memberReady := member.next(t, protocol.MessageLinkReady)
	machineReady := machine.next(t, protocol.MessageLinkReady)
	if memberReady.PeerKey != machine.key || memberReady.Observed == nil || memberReady.PunchAt == "" {
		t.Fatalf("member ready = %+v", memberReady)
	}
	if machineReady.PeerKey != member.key || machineReady.Observed == nil {
		t.Fatalf("machine ready = %+v", machineReady)
	}
	if !member.client.Online() || !machine.client.Online() {
		t.Fatal("presence dropped during the link")
	}
}

// The node refuses an open toward an absent device without a request id: the
// open gets the error and presence stays up.
func TestOpenLinkToAnAbsentDeviceFailsWithoutDroppingPresence(t *testing.T) {
	address, cleanup := runNodeServer(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	member := startLinkDevice(t, ctx, address)
	absent, _ := identity.Generate()
	_, err := member.client.OpenLink(ctx, hubGrant(t, member.key, serviceKey(t, absent)))
	var linkErr *LinkError
	if !errors.As(err, &linkErr) || linkErr.Code != "peer_offline" {
		t.Fatalf("err = %v, want peer_offline", err)
	}
	time.Sleep(200 * time.Millisecond)
	if !member.client.Online() {
		t.Fatal("presence dropped after a refused open")
	}
}
