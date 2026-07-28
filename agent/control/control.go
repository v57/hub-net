// Package control exposes hub-net status and configuration through its Hub
// service connection.
package control

import (
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/v57/channel-go/channelgo"
	"github.com/v57/hub-net/connection"
	"github.com/v57/hub-net/profile"
	"github.com/v57/hub-net/wireguard"
	hubservice "github.com/v57/hub-service-go"
	"github.com/v57/hub-service-go/service"
)

const (
	ProfilePath          = "hub-net/profile"
	PeersPath            = "hub-net/peers"
	SharesPath           = "hub-net/shares"
	HealthPath           = "hub-net/health"
	DiagnosticsPath      = "hub-net/diagnostics"
	NodeConfigPath       = "hub-net/node/config"
	NodeConfigUpdatePath = "hub-net/node/config/update"
)

type NodeConfig struct {
	Enabled   bool     `json:"enabled"`
	Endpoints []string `json:"endpoints"`
}

type ProfileState struct {
	State          profile.State `json:"state"`
	ProfileKey     string        `json:"profileKey"`
	WireGuardKey   string        `json:"wireGuardKey"`
	RegisteredAt   time.Time     `json:"registeredAt,omitempty"`
	Generation     uint64        `json:"generation"`
	OverlayAddress string        `json:"overlayAddress,omitempty"`
	HubNetworkID   string        `json:"hubNetworkId,omitempty"`
}

type PeerState struct {
	ResourceID string    `json:"resourceId"`
	ProviderID string    `json:"providerId"`
	PublicKey  string    `json:"publicKey"`
	Endpoint   string    `json:"endpoint"`
	LastUsed   time.Time `json:"lastUsed"`
}

type ShareHealth struct {
	ResourceID string `json:"resourceId"`
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Healthy    bool   `json:"healthy"`
	Message    string `json:"message,omitempty"`
}

type Health struct {
	Available      bool          `json:"available"`
	ProfileState   profile.State `json:"profileState"`
	WireGuardUp    bool          `json:"wireGuardUp"`
	Peers          int           `json:"peers"`
	Shares         int           `json:"shares"`
	LastDiagnostic string        `json:"lastDiagnostic,omitempty"`
}

type Options struct {
	Profile     *profile.Profile
	Adapter     wireguard.Adapter
	Connections *connection.Manager
	Shares      func() []ShareHealth
	NodeConfig  NodeConfig
}

type Controller struct {
	mu          sync.RWMutex
	profile     *profile.Profile
	adapter     wireguard.Adapter
	connections *connection.Manager
	shares      func() []ShareHealth
	nodeConfig  NodeConfig
}

func New(options Options) (*Controller, error) {
	if options.Profile == nil || options.Adapter == nil {
		return nil, errors.New("control: profile and adapter required")
	}
	return &Controller{
		profile: options.Profile, adapter: options.Adapter,
		connections: options.Connections, shares: options.Shares,
		nodeConfig: cloneNodeConfig(options.NodeConfig),
	}, nil
}

func (c *Controller) Register(svc *hubservice.Service) error {
	if svc == nil {
		return errors.New("control: service required")
	}
	view := service.Settings{Permissions: &service.Permissions{
		Group: "hub-net", Name: "view-status",
	}}
	manage := service.Settings{Permissions: &service.Permissions{
		Group: "hub-net", Name: "manage-node-config",
	}}
	svc.Stream(ProfilePath, c.stream(func() any { return c.Profile() }), view)
	svc.Stream(PeersPath, c.stream(func() any { return c.Peers() }), view)
	svc.Stream(SharesPath, c.stream(func() any { return c.Shares() }), view)
	svc.Stream(HealthPath, c.stream(func() any { return c.Health() }), view)
	svc.Stream(DiagnosticsPath, c.stream(func() any { return c.Diagnostics() }), view)
	svc.Post(NodeConfigPath, func(channelgo.Body) (any, error) {
		return c.NodeConfig(), nil
	}, view)
	svc.Post(NodeConfigUpdatePath, c.updateNodeConfig, manage)
	return nil
}

func (c *Controller) stream(snapshot func() any) channelgo.StreamFunction {
	return func(_ channelgo.Body, emit channelgo.StreamEmitter) error {
		if emit.IsCancelled() {
			return nil
		}
		return emit.Emit(snapshot())
	}
}

func (c *Controller) Profile() ProfileState {
	snapshot := c.profile.Snapshot()
	return ProfileState{
		State: snapshot.State, ProfileKey: snapshot.ProfileKey,
		WireGuardKey: base64.StdEncoding.EncodeToString(snapshot.WireGuardPubKey),
		RegisteredAt: snapshot.RegisteredAt, Generation: snapshot.Generation,
		OverlayAddress: snapshot.OverlayAddress, HubNetworkID: snapshot.HubNetworkID,
	}
}

func (c *Controller) Peers() []PeerState {
	if c.connections == nil {
		return []PeerState{}
	}
	peers := c.connections.Peers()
	out := make([]PeerState, 0, len(peers))
	for _, peer := range peers {
		out = append(out, PeerState{
			ResourceID: peer.ResourceID, ProviderID: peer.ProviderID,
			PublicKey: base64.StdEncoding.EncodeToString(peer.PublicKey),
			Endpoint:  peer.Endpoint, LastUsed: peer.LastUsed,
		})
	}
	return out
}

func (c *Controller) Shares() []ShareHealth {
	if c.shares == nil {
		return []ShareHealth{}
	}
	shares := c.shares()
	return append([]ShareHealth(nil), shares...)
}

func (c *Controller) Diagnostics() []connection.Diagnostic {
	if c.connections == nil {
		return []connection.Diagnostic{}
	}
	return c.connections.Diagnostics()
}

func (c *Controller) Health() Health {
	_, wireGuardUp := c.adapter.State()
	diagnostics := c.Diagnostics()
	shares := c.Shares()
	health := Health{
		Available:    c.profile.State() == profile.StateRegistered && wireGuardUp,
		ProfileState: c.profile.State(), WireGuardUp: wireGuardUp,
		Peers: len(c.Peers()), Shares: len(shares),
	}
	if len(diagnostics) > 0 {
		health.LastDiagnostic = diagnostics[len(diagnostics)-1].Code
	}
	return health
}

func (c *Controller) NodeConfig() NodeConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneNodeConfig(c.nodeConfig)
}

func (c *Controller) updateNodeConfig(body channelgo.Body) (any, error) {
	value, ok := body.Body.(map[string]any)
	if !ok {
		return nil, errors.New("control: invalid node config")
	}
	enabled, ok := value["enabled"].(bool)
	if !ok {
		return nil, errors.New("control: node config enabled required")
	}
	rawEndpoints, ok := value["endpoints"].([]any)
	if !ok {
		return nil, errors.New("control: node config endpoints required")
	}
	endpoints := make([]string, len(rawEndpoints))
	for i, raw := range rawEndpoints {
		endpoint, ok := raw.(string)
		if !ok || endpoint == "" {
			return nil, errors.New("control: node config endpoint must be non-empty string")
		}
		endpoints[i] = endpoint
	}
	c.mu.Lock()
	c.nodeConfig = NodeConfig{Enabled: enabled, Endpoints: endpoints}
	result := cloneNodeConfig(c.nodeConfig)
	c.mu.Unlock()
	return result, nil
}

func cloneNodeConfig(config NodeConfig) NodeConfig {
	config.Endpoints = append([]string(nil), config.Endpoints...)
	return config
}
