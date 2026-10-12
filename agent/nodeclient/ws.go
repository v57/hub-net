package nodeclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/v57/hub-net-node/protocol"
)

// rendezvousPath is the node's WebSocket endpoint. The client appends it when
// the configured endpoint carries no explicit path.
const rendezvousPath = "/rendezvous"

// DialWebSocket opens a client WebSocket to the node's rendezvous endpoint and
// returns the raw connection. Frames are masked per RFC 6455; the node's
// transport/ws accepts standard unmasked server frames.
func DialWebSocket(ctx context.Context, endpoint string) (net.Conn, error) {
	target, err := normalizeEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	address := target.Host
	var conn net.Conn
	if target.Scheme == "wss" {
		dialer := &tls.Dialer{}
		conn, err = dialer.DialContext(ctx, "tcp", address)
	} else {
		dialer := &net.Dialer{}
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, fmt.Errorf("nodeclient: dial %s: %w", address, err)
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	request := "GET " + target.RequestURI() + " HTTP/1.1\r\n" +
		"Host: " + target.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n\r\n"
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := io.WriteString(conn, request); err != nil {
		conn.Close()
		return nil, fmt.Errorf("nodeclient: websocket handshake: %w", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet, URL: target})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("nodeclient: websocket handshake: %w", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("nodeclient: websocket handshake status %s", response.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func normalizeEndpoint(endpoint string) (*url.URL, error) {
	value := strings.TrimSpace(endpoint)
	if value == "" {
		return nil, errors.New("nodeclient: empty endpoint")
	}
	if !strings.Contains(value, "://") {
		value = "ws://" + value
	}
	target, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: endpoint %q: %w", endpoint, err)
	}
	switch target.Scheme {
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("nodeclient: unsupported endpoint scheme %q", target.Scheme)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("nodeclient: endpoint %q missing host", endpoint)
	}
	if target.Path == "" || target.Path == "/" {
		target.Path = rendezvousPath
	}
	return target, nil
}

// envelopeWriteTimeout bounds one envelope write.
const envelopeWriteTimeout = 10 * time.Second

// WriteEnvelope encodes one protocol envelope as a single masked text frame.
// Each write gets its own deadline and clears it afterwards: the registration
// connection lives for hours, and a deadline left behind by one write would
// fail every later write on it.
func WriteEnvelope(conn net.Conn, envelope protocol.Envelope) error {
	_ = conn.SetWriteDeadline(time.Now().Add(envelopeWriteTimeout))
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	mask := [4]byte{}
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header := []byte{0x81}
	switch {
	case len(payload) <= 125:
		header = append(header, 0x80|byte(len(payload)))
	case len(payload) <= 65535:
		header = append(header, 0x80|126, 0, 0)
		binary.BigEndian.PutUint16(header[2:], uint16(len(payload)))
	default:
		return errors.New("nodeclient: envelope too large")
	}
	header = append(header, mask[:]...)
	masked := bytes.Clone(payload)
	for i := range masked {
		masked[i] ^= mask[i%4]
	}
	_, err = conn.Write(append(header, masked...))
	return err
}

// ReadEnvelope reads one server text frame and decodes it as an envelope.
func ReadEnvelope(conn net.Conn) (protocol.Envelope, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return protocol.Envelope{}, err
	}
	if header[0]&0x0f != 1 || header[1]&0x80 != 0 {
		return protocol.Envelope{}, errors.New("nodeclient: unexpected WebSocket frame")
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(conn, extended[:]); err != nil {
			return protocol.Envelope{}, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(conn, extended[:]); err != nil {
			return protocol.Envelope{}, err
		}
		length = binary.BigEndian.Uint64(extended[:])
	}
	if length > protocol.DefaultMaxMessageBytes {
		return protocol.Envelope{}, errors.New("nodeclient: server frame too large")
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(conn, payload); err != nil {
		return protocol.Envelope{}, err
	}
	var envelope protocol.Envelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return protocol.Envelope{}, fmt.Errorf("nodeclient: decode envelope: %w", err)
	}
	return envelope, nil
}
