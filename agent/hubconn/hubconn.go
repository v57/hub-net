// Package hubconn connects the agent to its Hub through the hub-service-go SDK.
//
// The SDK handles the connection, auth header and service registration. This
// package adds what the agent needs on top: an Ed25519 identity as the signer,
// handlers that see the whole channel body, typed calls, and Hub Network share
// publication that is republished on every reconnect.
package hubconn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/v57/channel-go/channelgo"
	"github.com/v57/hub-net-node/identity"
	"github.com/v57/hub-net/hubconn/network"
	hubservice "github.com/v57/hub-service-go"
)

const (
	// republishTimeout bounds the share republish after a reconnect.
	republishTimeout = 30 * time.Second
)

var (
	errNotStarted   = errors.New("hubconn: service not started")
	errStreamEnded  = errors.New("hubconn: stream ended before first value")
	errNoIdentity   = errors.New("hubconn: identity is required")
	errStartedTwice = errors.New("hubconn: already started")
)

// Options configures a Service.
type Options struct {
	// Address is the Hub address (port number, host:port or URL); 1997 when nil.
	Address any
	// Name and Icon are sent to the Hub as the service profile.
	Name string
	Icon any
	// Identity signs the auth token and share publications. Required.
	Identity *identity.Identity
	// HubKeysPath pins the hub's key so auth tokens are bound to it (v1).
	// Empty keeps the pin in memory for this process.
	HubKeysPath string
	// Device certifies Identity with this device's key on every connect, so
	// the hub attaches the connection to the device. Nil connects as a plain
	// key.
	Device *hubservice.DeviceKey
	// Instance names this service on its device. Defaults to Name.
	Instance string
	// NetworkOptions configures share publication (agent socket, timeouts).
	NetworkOptions network.Options
	// OnConnect runs after every (re)connect, once the service is registered
	// and its shares are republished.
	OnConnect func(sender *channelgo.Sender)
}

// Permissions is the Hub permission an API requires.
type Permissions struct {
	Group  string
	Name   string
	Allows bool
}

// Settings configures one API.
type Settings struct {
	Permissions *Permissions
	Limit       int
}

// Service is the agent's connection to its Hub.
type Service struct {
	svc      *hubservice.Service
	identity *identity.Identity
	network  *network.Publisher

	mu      sync.Mutex
	started bool
}

// New creates a Service; Start connects it.
func New(options Options) (*Service, error) {
	id := options.Identity
	if id == nil {
		return nil, errNoIdentity
	}
	s := &Service{identity: id, network: network.New(options.NetworkOptions)}
	onConnect := options.OnConnect
	instance := options.Instance
	if instance == "" {
		instance = options.Name
	}
	s.svc = hubservice.New(hubservice.ServiceOptions{
		Address: options.Address,
		Name:    options.Name,
		Icon:    options.Icon,
		Key:     id.PrivateKey(),
		HubKeys: options.HubKeysPath,
		Device: hubservice.DeviceOptions{
			Disabled: options.Device == nil,
			Key:      options.Device,
			Instance: instance,
		},
		OnConnect: func(sender *channelgo.Sender) {
			s.republish(sender)
			if onConnect != nil {
				onConnect(sender)
			}
		},
	})
	return s, nil
}

// Identity is the identity the service signs with.
func (s *Service) Identity() *identity.Identity { return s.identity }

// HubKey is the hub's pinned key, "" until the first connect learns it.
func (s *Service) HubKey() string { return s.svc.HubKey() }

// Sender is the Hub connection's sender, nil before Start and after Stop.
func (s *Service) Sender() *channelgo.Sender { return s.svc.Sender() }

// Post registers a request/response API.
func (s *Service) Post(path string, action channelgo.Function, settings Settings) {
	s.svc.Post(path, func(body any) (any, error) {
		return action(channelgo.Body{Body: body})
	}, apiSettings(settings))
}

// Stream registers a streaming API. The emitter reports cancellation once the
// caller cancels the stream.
func (s *Service) Stream(path string, action channelgo.StreamFunction, settings Settings) {
	s.svc.StreamContext(path, func(ctx context.Context, body any, emit func(any) error) error {
		return action(channelgo.Body{Body: body}, emitter{ctx: ctx, emit: emit})
	}, apiSettings(settings))
}

type emitter struct {
	ctx  context.Context
	emit func(any) error
}

func (e emitter) Emit(value any) error { return e.emit(value) }
func (e emitter) IsCancelled() bool    { return e.ctx.Err() != nil }

func apiSettings(settings Settings) hubservice.ApiSettings {
	var result hubservice.ApiSettings
	if settings.Limit != 0 {
		limit := settings.Limit
		result.Limit = &limit
	}
	if p := settings.Permissions; p != nil {
		permissions := &hubservice.ServicePermissions{Group: p.Group, Name: p.Name}
		if p.Allows {
			allows := true
			permissions.Allows = &allows
		}
		result.Permissions = permissions
	}
	return result
}

// Start connects to the Hub. It reconnects on its own until Stop.
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errStartedTwice
	}
	s.started = true
	s.svc.Start()
	return nil
}

// Stop closes the Hub connection.
func (s *Service) Stop() {
	s.mu.Lock()
	s.started = false
	s.mu.Unlock()
	s.svc.Stop()
}

// Send calls an API through the Hub.
func (s *Service) Send(path string, body any, contextValue ...any) (any, error) {
	return s.svc.Send(path, body, contextValue...)
}

// SendTyped calls an API and decodes its response into T.
func SendTyped[T any](s *Service, path string, body any, contextValue ...any) (T, error) {
	var zero T
	value, err := s.Send(path, body, contextValue...)
	if err != nil || value == nil {
		return zero, err
	}
	if typed, ok := value.(T); ok {
		return typed, nil
	}
	result, err := decode[T](value)
	if err != nil {
		return zero, fmt.Errorf("hubconn: decode %s response: %w", path, err)
	}
	return result, nil
}

// OneValue opens a stream and returns its first value.
func (s *Service) OneValue(ctx context.Context, path string, body any, contextValue ...any) (any, error) {
	values, err := s.svc.Values(path, body, contextValue...)
	if err != nil {
		return nil, err
	}
	defer values.Return()
	value, err := values.Next(ctx)
	if err != nil {
		return nil, err
	}
	if value.Done && value.Value == nil {
		return nil, errStreamEnded
	}
	return value.Value, nil
}

// OneValueTyped opens a stream and decodes its first value into T.
func OneValueTyped[T any](ctx context.Context, s *Service, path string, body any, contextValue ...any) (T, error) {
	var zero T
	value, err := s.OneValue(ctx, path, body, contextValue...)
	if err != nil {
		return zero, err
	}
	return decode[T](value)
}

func decode[T any](value any) (T, error) {
	var result T
	data, err := json.Marshal(value)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result)
	return result, err
}

// Share declares a share that is published on every connect.
func (s *Service) Share(name string, protocol network.Protocol, host string, port uint16, policy *network.Policy) *Service {
	s.network.Declare(network.Share{Name: name, Protocol: protocol, Host: host, Port: port, Policy: policy})
	return s
}

// PublishShare declares a share and publishes it now.
func (s *Service) PublishShare(ctx context.Context, name string, protocol network.Protocol, host string, port uint16, policy *network.Policy) ([]network.Publication, error) {
	sender := s.Sender()
	if sender == nil {
		return nil, errNotStarted
	}
	serviceKey, err := s.identity.PublicKeyBase64()
	if err != nil {
		return nil, err
	}
	share := network.Share{Name: name, Protocol: protocol, Host: host, Port: port, Policy: policy}
	return s.network.Publish(ctx, share, serviceKey, s.identity, sender)
}

// RemoveShare stops publishing a share and withdraws it from the Hub.
func (s *Service) RemoveShare(ctx context.Context, name string) ([]network.Publication, error) {
	sender := s.Sender()
	if sender == nil {
		return nil, errNotStarted
	}
	serviceKey, err := s.identity.PublicKeyBase64()
	if err != nil {
		return nil, err
	}
	return s.network.Remove(ctx, name, serviceKey, s.identity, sender)
}

// Network is the share publisher.
func (s *Service) Network() *network.Publisher { return s.network }

// republish sends the declared shares again after a reconnect.
func (s *Service) republish(sender *channelgo.Sender) {
	if !s.network.HasShares() {
		return
	}
	serviceKey, err := s.identity.PublicKeyBase64()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), republishTimeout)
	defer cancel()
	_, _ = s.network.Republish(ctx, serviceKey, s.identity, sender)
}
