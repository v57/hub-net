package nodeclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	hubprotocol "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
)

// ErrNotPresent is returned for link messages while the device holds no
// presence registration.
var ErrNotPresent = errors.New("nodeclient: not present at the node")

// LinkOpened is the node's answer to link.open: the link, this side's own
// probe token and the other side's service key.
type LinkOpened struct {
	LinkID     string
	ProbeToken string
	PeerKey    string
}

// LinkError is the node's error about one link request.
type LinkError struct {
	Code      string
	Message   string
	Retryable bool
}

func (e *LinkError) Error() string { return fmt.Sprintf("nodeclient: link: %s %s", e.Code, e.Message) }

// OpenLink sends link.open with grant on the presence connection and waits
// for link.opened.
func (c *Client) OpenLink(ctx context.Context, grant hubprotocol.PeerLinkGrant) (LinkOpened, error) {
	requestID := newRequestID()
	answer := make(chan protocol.Envelope, 1)
	c.mu.Lock()
	conn := c.conn
	if conn == nil || !c.online {
		c.mu.Unlock()
		return LinkOpened{}, ErrNotPresent
	}
	if c.waiters == nil {
		c.waiters = make(map[string]chan protocol.Envelope)
	}
	c.waiters[requestID] = answer
	c.opening = append(c.opening, requestID)
	c.mu.Unlock()
	defer c.forget(requestID)
	if err := c.write(conn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
		Type: protocol.MessageLinkOpen, RequestID: requestID, Grant: &grant,
	}); err != nil {
		return LinkOpened{}, fmt.Errorf("nodeclient: link.open: %w", err)
	}
	timer := time.NewTimer(handshakeTimeout)
	defer timer.Stop()
	select {
	case reply := <-answer:
		if reply.Type == protocol.MessageError {
			return LinkOpened{}, linkError(reply)
		}
		if reply.LinkID == "" || reply.ProbeToken == "" || reply.PeerKey == "" {
			return LinkOpened{}, errors.New("nodeclient: incomplete link.opened")
		}
		return LinkOpened{LinkID: reply.LinkID, ProbeToken: reply.ProbeToken, PeerKey: reply.PeerKey}, nil
	case <-timer.C:
		return LinkOpened{}, errors.New("nodeclient: link.open: the node did not answer")
	case <-ctx.Done():
		return LinkOpened{}, ctx.Err()
	}
}

// SendLink sends link.accept, link.reject, link.offer or link.close for
// linkID. Only link.offer carries endpoints. The node answers these only with
// an error, which reaches the Links handler.
func (c *Client) SendLink(messageType protocol.MessageType, linkID string, endpoints []hubprotocol.LinkEndpoint) error {
	switch messageType {
	case protocol.MessageLinkAccept, protocol.MessageLinkReject, protocol.MessageLinkClose:
		endpoints = nil
	case protocol.MessageLinkOffer:
	default:
		return fmt.Errorf("nodeclient: %s is not a link message", messageType)
	}
	c.mu.RLock()
	conn := c.conn
	online := c.online
	c.mu.RUnlock()
	if conn == nil || !online {
		return ErrNotPresent
	}
	return c.write(conn, protocol.Envelope{
		MajorVersion: protocol.MajorVersion, MinorVersion: protocol.MinorVersion,
		Type: messageType, RequestID: newRequestID(), LinkID: linkID, Endpoints: endpoints,
	})
}

// NodeUDPAddress resolves the node's UDP port, where link probes go: the
// host and port of its WebSocket endpoint.
func (c *Client) NodeUDPAddress(ctx context.Context) (netip.AddrPort, error) {
	endpoint := c.Endpoint()
	if endpoint == "" {
		return netip.AddrPort{}, ErrNotPresent
	}
	target, err := normalizeEndpoint(endpoint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	host := target.Host
	if target.Port() == "" {
		port := "80"
		if target.Scheme == "wss" {
			port = "443"
		}
		host = net.JoinHostPort(target.Hostname(), port)
	}
	address, err := net.DefaultResolver.LookupNetIP(ctx, "ip", target.Hostname())
	if err != nil || len(address) == 0 {
		return netip.AddrPort{}, fmt.Errorf("nodeclient: resolve %s: %w", host, err)
	}
	_, portText, _ := net.SplitHostPort(host)
	var port uint16
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil || port == 0 {
		return netip.AddrPort{}, fmt.Errorf("nodeclient: node port %q", portText)
	}
	// Prefer IPv4, as the WebSocket dial does by default
	for _, candidate := range address {
		if candidate.Unmap().Is4() {
			return netip.AddrPortFrom(candidate.Unmap(), port), nil
		}
	}
	return netip.AddrPortFrom(address[0], port), nil
}

// write serializes envelope writes: the read loop, bootstrap exchanges and
// link calls share the presence connection.
func (c *Client) write(conn net.Conn, envelope protocol.Envelope) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return WriteEnvelope(conn, envelope)
}

func (c *Client) forget(requestID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.waiters, requestID)
	for index, id := range c.opening {
		if id == requestID {
			c.opening = append(c.opening[:index], c.opening[index+1:]...)
			break
		}
	}
}

// dispatch hands link traffic to its waiter or the Links handler and reports
// whether it took the envelope. Every read on the presence connection calls
// it first, so links keep working during registration renewals and
// bootstrap exchanges.
func (c *Client) dispatch(envelope protocol.Envelope) bool {
	switch envelope.Type {
	case protocol.MessageLinkOpened:
		c.deliver(envelope.RequestID, envelope)
		return true
	case protocol.MessageLinkIncoming, protocol.MessageLinkReady, protocol.MessageLinkClosed:
		if c.opts.Links != nil {
			c.opts.Links(envelope)
		}
		return true
	case protocol.MessageError:
		if envelope.RequestID != "" && c.deliver(envelope.RequestID, envelope) {
			return true
		}
		if envelope.LinkID != "" {
			if c.opts.Links != nil {
				c.opts.Links(envelope)
			}
			return true
		}
		// The node answers a refused link.open without its request id: it
		// belongs to the oldest open still waiting
		c.mu.RLock()
		var oldest string
		if len(c.opening) > 0 {
			oldest = c.opening[0]
		}
		c.mu.RUnlock()
		if oldest != "" {
			return c.deliver(oldest, envelope)
		}
	}
	return false
}

func (c *Client) deliver(requestID string, envelope protocol.Envelope) bool {
	c.mu.RLock()
	answer, ok := c.waiters[requestID]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case answer <- envelope:
	default:
	}
	return true
}

func linkError(reply protocol.Envelope) error {
	if reply.Error == nil {
		return &LinkError{Code: "unknown", Message: "error without details"}
	}
	return &LinkError{Code: reply.Error.Code, Message: reply.Error.Message, Retryable: reply.Error.Retryable}
}
