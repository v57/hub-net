package dnsresolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	typeA    = 1
	typeAAAA = 28
	classIN  = 1
)

// Exchange forwards an ordinary DNS packet and returns the upstream response.
type Exchange func(context.Context, []byte) ([]byte, error)

// Server serves DNS over UDP and owns split-DNS install/teardown.
type Server struct {
	Resolver  *Resolver
	Installer Installer
	Upstream  Exchange

	mu        sync.Mutex
	conn      net.PacketConn
	cancel    context.CancelFunc
	started   bool
	installed bool
}

// Start binds address, installs suffix-scoped DNS, and serves until ctx ends.
func (s *Server) Start(ctx context.Context, address string) error {
	if err := s.StartUnconfigured(ctx, address); err != nil {
		return err
	}
	if err := s.Install(ctx); err != nil {
		_ = s.close(false, context.Background())
		return err
	}
	return nil
}

// StartUnconfigured binds and serves DNS without changing host split-DNS
// state. Production uses this before Hub registration because the WireGuard
// link does not exist until registration assigns an overlay address.
func (s *Server) StartUnconfigured(ctx context.Context, address string) error {
	if s.Resolver == nil || s.Installer == nil {
		return errors.New("dnsresolver: resolver and installer required")
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("dnsresolver: already started")
	}
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("dnsresolver: listen: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.conn, s.cancel, s.started = conn, cancel, true
	s.mu.Unlock()

	go s.serve(runCtx, conn)
	return nil
}

// Install applies split DNS to the already-running server. Reinstallation
// first reverts previous link state, supporting WireGuard link replacement on
// reconnect.
func (s *Server) Install(ctx context.Context) error {
	s.mu.Lock()
	if !s.started || s.conn == nil {
		s.mu.Unlock()
		return errors.New("dnsresolver: server not started")
	}
	address, installed := s.conn.LocalAddr(), s.installed
	s.mu.Unlock()
	if installed {
		if err := s.Installer.Remove(ctx); err != nil {
			return fmt.Errorf("dnsresolver: remove previous split DNS: %w", err)
		}
	}
	if err := s.Installer.Install(ctx, address, Suffix); err != nil {
		return fmt.Errorf("dnsresolver: install split DNS: %w", err)
	}
	s.mu.Lock()
	s.installed = true
	s.mu.Unlock()
	return nil
}

// Close removes split DNS and stops serving. It is idempotent.
func (s *Server) Close(ctx context.Context) error {
	return s.close(true, ctx)
}

func (s *Server) close(remove bool, ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	cancel, conn, installed := s.cancel, s.conn, s.installed
	s.mu.Unlock()
	cancel()
	closeErr := conn.Close()
	var removeErr error
	if remove && installed {
		removeErr = s.Installer.Remove(ctx)
	}
	s.Resolver.Deactivate()
	s.finish()
	return errors.Join(closeErr, removeErr)
}

func (s *Server) finish() {
	s.mu.Lock()
	s.conn, s.cancel, s.started, s.installed = nil, nil, false, false
	s.mu.Unlock()
}

func (s *Server) serve(ctx context.Context, conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			continue
		}
		request := append([]byte(nil), buf[:n]...)
		response, err := s.Handle(ctx, request)
		if err == nil {
			_, _ = conn.WriteTo(response, peer)
		}
	}
}

// Handle answers Hub names locally and delegates all unrelated packets
// byte-for-byte to Upstream.
func (s *Server) Handle(ctx context.Context, request []byte) ([]byte, error) {
	question, err := parseQuestion(request)
	if err != nil {
		return nil, err
	}
	if !IsHubName(question.name) {
		if s.Upstream == nil {
			return nil, ErrNotHubName
		}
		return s.Upstream(ctx, request)
	}
	record, lookupErr := s.Resolver.Lookup(question.name)
	rcode := byte(0)
	if lookupErr != nil {
		rcode = 3 // NXDOMAIN prevents public fallback for reserved names.
	}
	return buildResponse(request, question, record.Addresses, rcode)
}

type dnsQuestion struct {
	name        string
	qtype       uint16
	qclass      uint16
	questionEnd int
}

func parseQuestion(packet []byte) (dnsQuestion, error) {
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return dnsQuestion{}, errors.New("dnsresolver: malformed DNS question")
	}
	offset := 12
	var labels []string
	for {
		if offset >= len(packet) {
			return dnsQuestion{}, io.ErrUnexpectedEOF
		}
		size := int(packet[offset])
		offset++
		if size == 0 {
			break
		}
		if size > 63 || offset+size > len(packet) {
			return dnsQuestion{}, errors.New("dnsresolver: malformed DNS name")
		}
		labels = append(labels, string(packet[offset:offset+size]))
		offset += size
	}
	if offset+4 > len(packet) {
		return dnsQuestion{}, io.ErrUnexpectedEOF
	}
	return dnsQuestion{
		name:        stringsJoin(labels, "."),
		qtype:       binary.BigEndian.Uint16(packet[offset : offset+2]),
		qclass:      binary.BigEndian.Uint16(packet[offset+2 : offset+4]),
		questionEnd: offset + 4,
	}, nil
}

func buildResponse(request []byte, question dnsQuestion, addresses []net.IP, rcode byte) ([]byte, error) {
	response := append([]byte(nil), request[:question.questionEnd]...)
	flags := binary.BigEndian.Uint16(response[2:4])
	flags = (flags | 0x8000 | 0x0400) &^ 0x000f // response + authoritative
	flags |= uint16(rcode)
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	if rcode != 0 || question.qclass != classIN {
		return response, nil
	}
	for _, address := range addresses {
		var raw []byte
		switch question.qtype {
		case typeA:
			raw = address.To4()
		case typeAAAA:
			if address.To4() == nil {
				raw = address.To16()
			}
		}
		if raw == nil {
			continue
		}
		response = append(response, 0xc0, 0x0c)
		response = binary.BigEndian.AppendUint16(response, question.qtype)
		response = binary.BigEndian.AppendUint16(response, classIN)
		response = binary.BigEndian.AppendUint32(response, 5)
		response = binary.BigEndian.AppendUint16(response, uint16(len(raw)))
		response = append(response, raw...)
		count := binary.BigEndian.Uint16(response[6:8])
		binary.BigEndian.PutUint16(response[6:8], count+1)
	}
	return response, nil
}

func stringsJoin(parts []string, separator string) string {
	if len(parts) == 0 {
		return ""
	}
	size := len(separator) * (len(parts) - 1)
	for _, part := range parts {
		size += len(part)
	}
	result := make([]byte, 0, size)
	for index, part := range parts {
		if index > 0 {
			result = append(result, separator...)
		}
		result = append(result, part...)
	}
	return string(result)
}
