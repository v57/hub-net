package hubnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"time"

	protocol "github.com/v57/hub-net-node/models"

	"github.com/v57/hub-net/deviceports"
	"github.com/v57/hub-net/enforcement"
	"github.com/v57/hub-net/peerlink"
)

// DevicePortsFile is the device's list, in the daemon's state directory.
const DevicePortsFile = "device-ports.json"

// devicePortsInterval is how soon `hub-net ports` takes effect on running links.
const devicePortsInterval = 3 * time.Second

// errPortNotAllowed refuses a grant for a port this device doesn't let open.
var errPortNotAllowed = errors.New("hubnet: this device doesn't let that port open")

func (a *Agent) openDevicePorts() error {
	path := a.devicePortsPath
	if path == "" {
		path = filepath.Join(a.config.StateDir, DevicePortsFile)
	}
	list, err := deviceports.Open(path)
	if err != nil {
		return err
	}
	a.devicePorts = list
	return nil
}

// sharePorts are the shares this device publishes itself.
func (a *Agent) sharePorts() []deviceports.Port {
	a.mu.Lock()
	service := a.hubService
	a.mu.Unlock()
	ports := make([]deviceports.Port, 0, len(a.initialShares))
	for _, share := range a.initialShares {
		ports = append(ports, deviceports.Port{Protocol: share.Protocol, Port: share.Port})
	}
	if service != nil {
		for _, share := range service.Network().Declared() {
			ports = append(ports, deviceports.Port{Protocol: string(share.Protocol), Port: share.Port})
		}
	}
	return ports
}

// linkRules are the firewall rules for what linked devices may open here:
// what their grants name and this device lets open, from the other side's
// addresses to this device's.
func linkRules(peers []peerlink.Peer, own []netip.Addr, allowed func([]protocol.PeerLinkPort) []protocol.PeerLinkPort) []enforcement.Rule {
	var rules []enforcement.Rule
	expires := time.Now().AddDate(100, 0, 0)
	for _, peer := range peers {
		for _, port := range allowed(peer.Ports) {
			for _, source := range peer.Sources {
				for _, destination := range own {
					if !destination.IsValid() || source.Is4() != destination.Is4() {
						continue
					}
					rules = append(rules, enforcement.Rule{
						ResourceID: enforcement.LinkResourcePrefix + peer.Key, ProviderID: peer.Key,
						Source: source, Destination: destination, DestinationPort: uint16(port.Port), Protocol: port.Protocol,
						ExpiresAt: expires,
					})
				}
			}
		}
	}
	return rules
}

// applyLinkPorts installs the rules for these peers. The first link makes the
// firewall drop every other overlay port, also on a member; without a firewall
// backend (not Linux) nothing limits them, and the agent says so.
func (a *Agent) applyLinkPorts(peers []peerlink.Peer) error {
	a.mu.Lock()
	a.linkedPeers = peers
	own := []netip.Addr{a.interfaceAddress, a.interfaceIPv6}
	a.mu.Unlock()
	if a.enforcementMgr == nil {
		if len(peers) > 0 && !a.warnedNoFirewall.Swap(true) {
			a.logger.Warn("no firewall backend on this platform: linked devices aren't limited to the ports this device allows")
		}
		return nil
	}
	shares := a.sharePorts()
	if a.bindingKind == "" || a.bindingKind == protocol.LocalAgentBindingMachine {
		// The Hub on this very machine: its port stays open, AllowControl's too
		shares = append(shares, deviceports.Port{Protocol: "tcp", Port: hubPort(a.config.HubAddress)})
	}
	rules := linkRules(peers, own, func(ports []protocol.PeerLinkPort) []protocol.PeerLinkPort {
		var kept []protocol.PeerLinkPort
		for _, port := range ports {
			if a.devicePorts.Allows(deviceports.Port{Protocol: port.Protocol, Port: uint16(port.Port)}, shares) {
				kept = append(kept, port)
			} else {
				a.logger.Debug("link port refused: this device doesn't let it open", slog.String("port", fmt.Sprintf("%s/%d", port.Protocol, port.Port)))
			}
		}
		return kept
	})
	return a.enforcementMgr.SetLinkRules(rules)
}

// watchDevicePorts follows `hub-net ports` for the running links.
func (a *Agent) watchDevicePorts(ctx context.Context) {
	ticker := time.NewTicker(devicePortsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed, err := a.devicePorts.Reload()
			if err != nil {
				a.logger.Warn("device ports unreadable", slog.String("err", err.Error()))
				continue
			}
			if !changed {
				continue
			}
			a.mu.Lock()
			peers := a.linkedPeers
			a.mu.Unlock()
			if err := a.applyLinkPorts(peers); err != nil {
				a.logger.Warn("link ports not applied", slog.String("err", err.Error()))
			}
		}
	}
}
