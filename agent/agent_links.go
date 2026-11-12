package hubnet

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/v57/channel-go/channelgo"
	"github.com/v57/hub-net-node/models"
	nodeprotocol "github.com/v57/hub-net-node/protocol"

	"github.com/v57/hub-net/nodeclient"
	"github.com/v57/hub-net/peerlink"
	"github.com/v57/hub-net/wireguard"
)

// linkKeepalive keeps the NAT mapping of a linked peer open, as the Apple
// app's tunnel does.
const linkKeepalive = 25

// peerLinksState is network/links: the grants the hub issued this device,
// where to meet the other sides, and whether this device is the hub's machine.
type peerLinksState struct {
	Version      int                    `json:"version"`
	HubKey       string                 `json:"hubKey"`
	HubNetworkID string                 `json:"hubNetworkId"`
	Coordinator  string                 `json:"coordinator"`
	HubHost      bool                   `json:"hubHost"`
	Grants       []models.PeerLinkGrant `json:"grants"`
	// PresenceSecret is what this device and its Hub share, so the node says nothing about either to anyone else.
	PresenceSecret string `json:"presenceSecret,omitempty"`
}

// newLinkManager builds this session's peer link manager. It reaches the
// node through the presence client, which is created after it.
func (a *Agent) newLinkManager() (*peerlink.Manager, error) {
	ownKey, err := a.profileID.PublicKeyBase64()
	if err != nil {
		return nil, err
	}
	return peerlink.New(ownKey, peerlink.Dependencies{
		Open: func(ctx context.Context, grant models.PeerLinkGrant) (peerlink.Opened, error) {
			if a.nodeClient == nil {
				return peerlink.Opened{}, nodeclient.ErrNotPresent
			}
			opened, err := a.nodeClient.OpenLink(ctx, grant)
			return peerlink.Opened{LinkID: opened.LinkID, ProbeToken: opened.ProbeToken, PeerKey: opened.PeerKey}, err
		},
		Send: func(messageType nodeprotocol.MessageType, linkID string, endpoints []models.LinkEndpoint) error {
			if a.nodeClient == nil {
				return nodeclient.ErrNotPresent
			}
			return a.nodeClient.SendLink(messageType, linkID, endpoints)
		},
		Probe: func(ctx context.Context, payload []byte) error {
			if a.nodeClient == nil {
				return nodeclient.ErrNotPresent
			}
			node, err := a.nodeClient.NodeUDPAddress(ctx)
			if err != nil {
				return err
			}
			return wireguard.SendFromPort(a.listenPort(), node, payload)
		},
		Apply:         a.applyLinkPeers,
		LastHandshake: a.lastHandshake,
		LiveEndpoint:  a.liveEndpoint,
		Candidates:    a.linkCandidates,
		Logger:        a.logger,
	}), nil
}

// watchLinks follows network/links and hands the grants to the link manager,
// checked against the hub key this session registered with.
func (a *Agent) watchLinks(ctx context.Context, sender *channelgo.Sender) {
	if a.links == nil {
		return
	}
	values := sender.Values("network/links", nil)
	defer values.Return()
	for {
		item, err := values.Next(ctx)
		if err != nil || item.Done {
			if err != nil && ctx.Err() == nil {
				a.logger.Info("network/links unavailable", slog.String("err", err.Error()))
			}
			return
		}
		encoded, err := json.Marshal(item.Value)
		if err != nil {
			continue
		}
		var state peerLinksState
		if json.Unmarshal(encoded, &state) != nil {
			continue
		}
		a.setPresenceSecret(state.PresenceSecret)
		a.links.Update(a.profile.HubKey(), state.Grants)
	}
}

// PresenceSecretFile keeps the Hub's secret in the daemon's state directory, so a restart registers with its tags
// from the first message, also while the Hub is out of reach.
const PresenceSecretFile = "presence-secret"

func (a *Agent) presenceSecretPath() string {
	return filepath.Join(a.config.StateDir, PresenceSecretFile)
}

// loadPresenceSecret is what the last run's Hub gave. A file that's gone or unreadable just means no tags yet.
func (a *Agent) loadPresenceSecret() []byte {
	raw, err := os.ReadFile(a.presenceSecretPath())
	if err != nil {
		return nil
	}
	secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil
	}
	return secret
}

// setPresenceSecret follows network/links. A Hub that gives none (an older Hub) has members who can't hold one
// either, so the device goes back to answering everyone rather than vanish from them.
func (a *Agent) setPresenceSecret(encoded string) {
	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		a.logger.Warn("network/links: unreadable presence secret")
		return
	}
	if bytes.Equal(secret, a.loadPresenceSecret()) {
		if a.nodeClient != nil {
			_ = a.nodeClient.SetPresenceSecret(secret)
		}
		return
	}
	path := a.presenceSecretPath()
	if len(secret) == 0 {
		err = os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	} else if err = os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		err = writeSecretFile(path, encoded)
	}
	if err != nil {
		a.logger.Warn("presence secret not kept", slog.String("err", err.Error()))
	}
	if a.nodeClient != nil {
		if err := a.nodeClient.SetPresenceSecret(secret); err != nil {
			a.logger.Info("presence tags not sent", slog.String("err", err.Error()))
		}
	}
}

func writeSecretFile(path, value string) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".presence-secret-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0o600); err == nil {
		_, err = temp.WriteString(value)
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

func (a *Agent) listenPort() uint16 {
	if state, up := a.adapter.State(); up && state.ListenPort != 0 {
		return state.ListenPort
	}
	return wireguard.DefaultPort
}

// applyLinkPeers sets each linked device as a WireGuard peer with the
// endpoint being tried. A peer this session already has (the inviter's on a
// member, a member's on the hub's machine) keeps its routes; the link adds
// its own. A revoked device, or on the hub's machine one the hub no longer
// lists, is left out.
func (a *Agent) applyLinkPeers(peers []peerlink.Peer) error {
	state, up := a.adapter.State()
	if !up {
		return errors.New("hubnet: interface is down")
	}
	existing := make(map[string]wireguard.PeerConfig, len(state.Peers))
	for _, peer := range state.Peers {
		existing[base64.StdEncoding.EncodeToString(peer.PublicKey)] = peer
	}
	machine := a.bindingKind == "" || a.bindingKind == models.LocalAgentBindingMachine
	accepted := make([]peerlink.Peer, 0, len(peers))
	for _, peer := range peers {
		if !a.isRevokedPeer(peer.Key, peer.WireGuardKey) && (!machine || a.netUsers.Exists(peer.Key)) {
			accepted = append(accepted, peer)
		}
	}
	// The ports before the peers, so a new peer never finds this device open
	result := a.applyLinkPorts(accepted)
	for _, peer := range accepted {
		key, err := base64.StdEncoding.DecodeString(peer.WireGuardKey)
		if err != nil || len(key) != 32 {
			continue
		}
		current := existing[peer.WireGuardKey]
		allowed := append([]netip.Prefix(nil), current.AllowedIPs...)
		for _, route := range peer.Routes {
			if !containsPrefix(allowed, route) {
				allowed = append(allowed, route)
			}
		}
		endpoint := peer.Endpoint
		if endpoint == "" {
			endpoint = current.Endpoint
		}
		result = errors.Join(result, a.adapter.AddPeer(wireguard.PeerConfig{
			PublicKey: key, AllowedIPs: allowed, Endpoint: endpoint, PersistentKeepalive: linkKeepalive,
		}))
	}
	return result
}

func containsPrefix(prefixes []netip.Prefix, prefix netip.Prefix) bool {
	for _, existing := range prefixes {
		if existing == prefix {
			return true
		}
	}
	return false
}

func (a *Agent) lastHandshake(wireGuardKey string) (time.Time, bool) {
	reporter, ok := a.adapter.(wireguard.HandshakeReporter)
	if !ok {
		return time.Time{}, false
	}
	handshakes, err := reporter.LastHandshakes()
	if err != nil {
		return time.Time{}, false
	}
	at, ok := handshakes[wireGuardKey]
	return at, ok
}

// liveEndpoint is where WireGuard sends to the peer now: the profile's
// endpoint for the hub's machine, the one a link set, or where the peer's
// packets last came from.
func (a *Agent) liveEndpoint(wireGuardKey string) (string, bool) {
	reporter, ok := a.adapter.(wireguard.PeerStatusReporter)
	if !ok {
		return "", false
	}
	statuses, err := reporter.PeerStatuses()
	if err != nil {
		return "", false
	}
	endpoint := statuses[wireGuardKey].Endpoint
	if !endpoint.IsValid() {
		return "", false
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()).String(), true
}

// linkCandidates are this device's host candidates for link.offer: the
// configured advertise address, then each LAN address and global IPv6
// address of an interface that is up, with WireGuard's port. Overlay
// interfaces and addresses are left out.
func (a *Agent) linkCandidates() []models.LinkEndpoint {
	port := a.listenPort()
	var out []models.LinkEndpoint
	seen := make(map[string]bool)
	add := func(address netip.Addr) {
		address = address.Unmap()
		if !address.IsValid() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() ||
			wireguard.IPv4OverlayPrefix.Contains(address) || wireguard.IPv6OverlayPrefix.Contains(address) {
			return
		}
		if address.Is6() && !address.IsGlobalUnicast() {
			return
		}
		if seen[address.String()] || len(out) >= 16 {
			return
		}
		seen[address.String()] = true
		out = append(out, models.LinkEndpoint{Address: address.String(), Port: port})
	}
	if advertised, err := netip.ParseAddr(a.config.AdvertiseAddress); err == nil {
		add(advertised)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 ||
			iface.Name == a.interfaceName || strings.HasPrefix(iface.Name, "hubnet") {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil {
				add(prefix.Addr())
			}
		}
	}
	return out
}
