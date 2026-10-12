// Direct bootstrap UDP framing.
//
// The inviter runs a dedicated UDP listener that accepts framed, signed
// DirectBootstrapRequests and answers with framed DirectBootstrapResponses (or
// a framed network error). The same socket sends the inviter's invitation UDP
// probe to hub-net-node, so the node-observed endpoint the joiner learns
// through the paired session is exactly the listener's address and port.
//
// Frame layout (all integers big-endian):
//
//	offset 0:  magic  "HUBB" (4 bytes)
//	offset 4:  version 1 (1 byte)
//	offset 5:  type 1=request 2=response 3=error (1 byte)
//	offset 6:  requestId (16 bytes)
//	offset 22: payloadLength (4 bytes)
//	offset 26: payload (JSON)
//
// Request payload is protocol.DirectBootstrapRequest, response payload is
// protocol.DirectBootstrapResponse, error payload is protocol.NetworkError.
// A datagram is one frame; frames larger than MaxBootstrapFrameBytes are
// rejected before decode. The requestId correlates a response/error with the
// request that produced it and is echoed verbatim.
package invitation

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/v57/hub-service-go/protocol"
)

const (
	frameMagic     = "HUBB"
	frameVersion   = 1
	requestIDLen   = 16
	frameHeaderLen = 26
	// MaxBootstrapFrameBytes bounds one UDP bootstrap datagram. Direct
	// bootstrap payloads are a few hundred bytes; the cap leaves room for
	// future v2 fields while keeping the listener inside UDP datagram limits.
	MaxBootstrapFrameBytes = 64 * 1024
)

// FrameType identifies the direct bootstrap datagram kind.
type FrameType byte

const (
	FrameRequest  FrameType = 1
	FrameResponse FrameType = 2
	FrameError    FrameType = 3
)

func (t FrameType) String() string {
	switch t {
	case FrameRequest:
		return "request"
	case FrameResponse:
		return "response"
	case FrameError:
		return "error"
	default:
		return fmt.Sprintf("unknown(%d)", byte(t))
	}
}

// frame is one decoded direct bootstrap datagram.
type frame struct {
	Type      FrameType
	RequestID [requestIDLen]byte
	Payload   []byte
}

// newRequestID returns a fresh 16-byte request id.
func newRequestID() ([requestIDLen]byte, error) {
	var id [requestIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("invitation: request id: %w", err)
	}
	return id, nil
}

func requestIDString(id [requestIDLen]byte) string {
	return hex.EncodeToString(id[:])
}

func parseRequestID(value string) ([requestIDLen]byte, error) {
	var id [requestIDLen]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != requestIDLen {
		return id, errors.New("invitation: request id must be 16 bytes hex")
	}
	copy(id[:], raw)
	return id, nil
}

// marshalFrame encodes one frame. payload is JSON bytes.
func marshalFrame(typ FrameType, requestID [requestIDLen]byte, payload []byte) ([]byte, error) {
	if len(payload) > MaxBootstrapFrameBytes-frameHeaderLen {
		return nil, fmt.Errorf("invitation: bootstrap frame payload %d exceeds limit", len(payload))
	}
	if typ != FrameRequest && typ != FrameResponse && typ != FrameError {
		return nil, fmt.Errorf("invitation: invalid bootstrap frame type %d", byte(typ))
	}
	out := make([]byte, frameHeaderLen+len(payload))
	copy(out[0:4], frameMagic)
	out[4] = frameVersion
	out[5] = byte(typ)
	copy(out[6:22], requestID[:])
	binary.BigEndian.PutUint32(out[22:26], uint32(len(payload)))
	copy(out[26:], payload)
	return out, nil
}

// unmarshalFrame validates and decodes one datagram.
func unmarshalFrame(data []byte) (frame, error) {
	if len(data) > MaxBootstrapFrameBytes {
		return frame{}, fmt.Errorf("invitation: bootstrap frame %d exceeds limit", len(data))
	}
	if len(data) < frameHeaderLen {
		return frame{}, errors.New("invitation: bootstrap frame truncated")
	}
	if string(data[0:4]) != frameMagic {
		return frame{}, errors.New("invitation: bootstrap frame magic mismatch")
	}
	if data[4] != frameVersion {
		return frame{}, fmt.Errorf("invitation: unsupported bootstrap frame version %d", data[4])
	}
	typ := FrameType(data[5])
	if typ != FrameRequest && typ != FrameResponse && typ != FrameError {
		return frame{}, fmt.Errorf("invitation: invalid bootstrap frame type %d", data[5])
	}
	length := binary.BigEndian.Uint32(data[22:26])
	if int(length) != len(data)-frameHeaderLen {
		return frame{}, errors.New("invitation: bootstrap frame length mismatch")
	}
	var requestID [requestIDLen]byte
	copy(requestID[:], data[6:22])
	payload := append([]byte(nil), data[26:]...)
	return frame{Type: typ, RequestID: requestID, Payload: payload}, nil
}

// decodeRequestPayload unmarshals a request frame payload.
func decodeRequestPayload(payload []byte) (protocol.DirectBootstrapRequest, error) {
	var request protocol.DirectBootstrapRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return request, fmt.Errorf("invitation: decode bootstrap request: %w", err)
	}
	return request, nil
}

// decodeResponsePayload unmarshals a response frame payload.
func decodeResponsePayload(payload []byte) (protocol.DirectBootstrapResponse, error) {
	var response protocol.DirectBootstrapResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return response, fmt.Errorf("invitation: decode bootstrap response: %w", err)
	}
	return response, nil
}

// encodeRequestPayload marshals a signed request for transport.
func encodeRequestPayload(request protocol.DirectBootstrapRequest) ([]byte, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("invitation: encode bootstrap request: %w", err)
	}
	return payload, nil
}

// encodeResponsePayload marshals a signed response for transport.
func encodeResponsePayload(response protocol.DirectBootstrapResponse) ([]byte, error) {
	payload, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("invitation: encode bootstrap response: %w", err)
	}
	return payload, nil
}
