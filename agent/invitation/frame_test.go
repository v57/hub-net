package invitation

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/v57/hub-service-go/protocol"
)

func TestFrameRoundTrip(t *testing.T) {
	requestID, err := newRequestID()
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.DirectBootstrapRequest{
		Version: bootstrapVersion, ReplayID: "replay",
		JoinerServiceKey: "joiner", JoinerWireGuardKey: "wg",
		Nonce: "n", IssuedAt: "now", Signature: "sig",
	}
	payload, err := encodeRequestPayload(request)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalFrame(FrameRequest, requestID, payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshalFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != FrameRequest {
		t.Fatalf("type = %s, want request", decoded.Type)
	}
	if decoded.RequestID != requestID {
		t.Fatal("request id mismatch")
	}
	got, err := decodeRequestPayload(decoded.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce != request.Nonce || got.ReplayID != request.ReplayID {
		t.Fatalf("request payload mismatch: %+v", got)
	}
}

func TestFrameRejects(t *testing.T) {
	requestID, _ := newRequestID()
	payload := []byte(`{"version":1}`)
	good, err := marshalFrame(FrameRequest, requestID, payload)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		mut  func([]byte) []byte
	}{
		{"bad magic", func(data []byte) []byte {
			out := append([]byte(nil), data...)
			copy(out[0:4], "GARB")
			return out
		}},
		{"bad version", func(data []byte) []byte {
			out := append([]byte(nil), data...)
			out[4] = 99
			return out
		}},
		{"bad type", func(data []byte) []byte {
			out := append([]byte(nil), data...)
			out[5] = 99
			return out
		}},
		{"truncated", func(data []byte) []byte {
			return data[:10]
		}},
		{"length mismatch", func(data []byte) []byte {
			out := append([]byte(nil), data...)
			binary.BigEndian.PutUint32(out[22:26], 7)
			return out
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := unmarshalFrame(test.mut(good)); err == nil {
				t.Fatal("expected decode error")
			}
		})
	}
}

func TestFrameOversizePayload(t *testing.T) {
	requestID, _ := newRequestID()
	payload := bytes.Repeat([]byte("x"), MaxBootstrapFrameBytes)
	if _, err := marshalFrame(FrameRequest, requestID, payload); err == nil {
		t.Fatal("expected oversize error")
	}
	oversized := make([]byte, MaxBootstrapFrameBytes+1)
	if _, err := unmarshalFrame(oversized); err == nil {
		t.Fatal("expected oversize decode error")
	}
}

func TestFrameErrorRoundTrip(t *testing.T) {
	requestID, _ := newRequestID()
	networkError := protocol.NetworkError{
		Version: protocol.WireVersion, Code: BootstrapErrorReplay,
		Message: "used", Retryable: false,
	}
	payload, err := json.Marshal(networkError)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalFrame(FrameError, requestID, payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshalFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var got protocol.NetworkError
	if err := decodeNetworkError(decoded.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != BootstrapErrorReplay || got.Retryable {
		t.Fatalf("error payload mismatch: %+v", got)
	}
}

func TestRequestIDParse(t *testing.T) {
	requestID, _ := newRequestID()
	value := requestIDString(requestID)
	parsed, err := parseRequestID(value)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != requestID {
		t.Fatal("parsed request id mismatch")
	}
	if _, err := parseRequestID("short"); err == nil {
		t.Fatal("expected short request id error")
	}
	if _, err := parseRequestID(strings.Repeat("z", 32)); err == nil {
		t.Fatal("expected non-hex request id error")
	}
}
