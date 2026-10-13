// Joiner direct bootstrap exchange.
//
// Exchange sends one signed DirectBootstrapRequest to the inviter's bootstrap
// listener over UDP framing and returns the verified
// DirectBootstrapResponse. The inviter handler is idempotent for an identical
// request (same replay id, nonce, joiner), so lost-datagram retries are safe.
package invitation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	protocol "github.com/v57/hub-net-node/models"
)

const (
	defaultExchangeTimeout = 5 * time.Second
	defaultExchangeRetries = 3
)

// ExchangeOptions configures one joiner bootstrap exchange.
type ExchangeOptions struct {
	// Timeout bounds each send/read attempt. Defaults to 5 seconds.
	Timeout time.Duration
	// Retries is the number of additional attempts after a timeout or
	// transient error. Defaults to 3.
	Retries int
	// Now is the clock used to verify the response. Defaults to time.Now.
	Now func() time.Time
}

// BootstrapTransportError is a wire-shaped error frame from the inviter. Code
// is one of the BootstrapError* constants; Retryable tells the joiner whether
// a retry can succeed.
type BootstrapTransportError struct {
	Code      string
	Message   string
	Retryable bool
}

func (e *BootstrapTransportError) Error() string {
	return fmt.Sprintf("bootstrap %s: %s", e.Code, e.Message)
}

// Exchange sends the signed request to the inviter listener address and waits
// for a verified response. It returns an error on transport failure, an error
// frame, or a response that fails VerifyInviterResponse.
func Exchange(ctx context.Context, address *net.UDPAddr, request protocol.DirectBootstrapRequest, options ExchangeOptions) (protocol.DirectBootstrapResponse, error) {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultExchangeTimeout
	}
	retries := options.Retries
	if retries < 0 {
		retries = 0
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	requestID, err := newRequestID()
	if err != nil {
		return protocol.DirectBootstrapResponse{}, err
	}
	payload, err := encodeRequestPayload(request)
	if err != nil {
		return protocol.DirectBootstrapResponse{}, err
	}
	frame, err := marshalFrame(FrameRequest, requestID, payload)
	if err != nil {
		return protocol.DirectBootstrapResponse{}, err
	}

	// An unconnected socket: an inviter on a multi-homed host (Docker bridges,
	// VPNs, several interfaces) may answer from another of its addresses, and
	// a connected socket would drop that reply. The response is signed by the
	// invitation key and checked below, so its source address is not trusted.
	network := "udp4"
	if address.IP.To4() == nil {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return protocol.DirectBootstrapResponse{}, fmt.Errorf("invitation: open bootstrap socket: %w", err)
	}
	defer conn.Close()

	attempts := retries + 1
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return protocol.DirectBootstrapResponse{}, err
		}
		if attempt > 0 {
			// Identical requests are idempotent on the inviter; a short pause
			// lets transient inviter capacity drain before the next attempt.
			if err := waitExchange(ctx, 50*time.Millisecond*time.Duration(attempt)); err != nil {
				return protocol.DirectBootstrapResponse{}, err
			}
		}
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := conn.WriteToUDP(frame, address); err != nil {
			lastErr = err
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		buffer := make([]byte, MaxBootstrapFrameBytes)
		for {
			n, source, err := conn.ReadFromUDP(buffer)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					lastErr = fmt.Errorf("invitation: bootstrap exchange timed out: %w", netErr)
					break
				}
				return protocol.DirectBootstrapResponse{}, err
			}
			reply, err := unmarshalFrame(buffer[:n])
			if err != nil {
				continue
			}
			if reply.RequestID != requestID {
				continue
			}
			switch reply.Type {
			case FrameResponse:
				response, err := decodeResponsePayload(reply.Payload)
				if err != nil {
					return protocol.DirectBootstrapResponse{}, err
				}
				if err := VerifyInviterResponse(response, request, now()); err != nil {
					return protocol.DirectBootstrapResponse{}, err
				}
				return response, nil
			case FrameError:
				// Error frames are unsigned: only the inviter's own address
				// may end the exchange with one.
				if !source.IP.Equal(address.IP) {
					continue
				}
				var networkError protocol.NetworkError
				if err := decodeNetworkError(reply.Payload, &networkError); err != nil {
					continue
				}
				return protocol.DirectBootstrapResponse{}, &BootstrapTransportError{
					Code: networkError.Code, Message: networkError.Message, Retryable: networkError.Retryable,
				}
			default:
				continue
			}
		}
	}
	return protocol.DirectBootstrapResponse{}, lastErr
}

func decodeNetworkError(payload []byte, out *protocol.NetworkError) error {
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("invitation: decode bootstrap error: %w", err)
	}
	if out.Version != protocol.WireVersion || out.Code == "" {
		return errors.New("invitation: invalid bootstrap error frame")
	}
	return nil
}

func waitExchange(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
