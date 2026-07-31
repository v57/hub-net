// Package ipc exposes the hub-net agent local IPC server.
//
// HN-302 implements the attestation flow:
//
//  1. service opens local IPC socket, requests challenge
//  2. agent issues nonce
//  3. service proves Hub identity by signing nonce with its Ed25519 key
//  4. agent verifies proof, verifies requested target is local
//  5. agent returns short-lived signed attestation binding service key,
//     agent key, share name, protocol, local target
//
// This scaffold defines the request/response models and the Server type;
// crypto verification lands with HN-302 proper. The server accepts local
// clients only — socket ownership/mode and peer credentials are checked in
// the platform binding (PLATFORMS.md safety requirements).
package ipc

import (
	"errors"
	"time"

	"github.com/v57/hub-service-go/protocol"
)

// MessageType labels a local IPC request.
type MessageType string

const (
	MessageChallenge      MessageType = "challenge"
	MessageAttestRequest  MessageType = "attest"
	MessageStatusRequest  MessageType = "status"
	MessageAttestResponse MessageType = "attestation"
	MessageBindingProof   MessageType = "binding-proof"
)

const (
	LocalBindingProofDomain = "hub-network/local-agent-binding/v1"
	BootstrapCapability     = "invitation-bootstrap-v1"
	LocalBindingProofTTL    = 30 * time.Second
)

// ChallengeRequest asks the agent for a nonce. ShareName, Protocol, and
// Target accompany the request on the wire (Bun, Swift, and Go SDK clients
// all send them) so the subsequent /attest call can be redeemed without the
// client echoing the nonce back.
type ChallengeRequest struct {
	Version    int                  `json:"version"`
	Type       MessageType          `json:"type"`
	ServiceKey string               `json:"serviceKey"`
	ShareName  string               `json:"shareName,omitempty"`
	Protocol   string               `json:"protocol,omitempty"`
	Target     protocol.LocalTarget `json:"target,omitempty"`
}

// ChallengeResponse carries the nonce to sign.
type ChallengeResponse struct {
	Version   int         `json:"version"`
	Type      MessageType `json:"type"`
	Nonce     string      `json:"nonce"`
	AgentKey  string      `json:"agentKey"`
	IssuedAt  time.Time   `json:"issuedAt"`
	ExpiresAt time.Time   `json:"expiresAt"`
}

// AttestRequest is the signed challenge plus the requested local target.
type AttestRequest struct {
	Version    int                  `json:"version"`
	Type       MessageType          `json:"type"`
	ServiceKey string               `json:"serviceKey"`
	ShareName  string               `json:"shareName"`
	Protocol   string               `json:"protocol"`
	Target     protocol.LocalTarget `json:"target"`
	Nonce      string               `json:"nonce"`
	Signature  string               `json:"signature"`
}

// AttestResponse returns the signed attestation.
type AttestResponse struct {
	Version     int                       `json:"version"`
	Type        MessageType               `json:"type"`
	Attestation protocol.AgentAttestation `json:"attestation"`
}

// StatusRequest queries agent health.
type StatusRequest struct {
	Version int         `json:"version"`
	Type    MessageType `json:"type"`
}

// Handler serves IPC requests. Implementations verify signatures and local
// targets; errors are returned as wire-level errors for the service to log.
type Handler interface {
	Challenge(req ChallengeRequest) (ChallengeResponse, error)
	Attest(req AttestRequest) (AttestResponse, error)
	Status(req StatusRequest) (StatusResponse, error)
	BindingProof(req BindingProofRequest) (BindingProofResponse, error)
}

// BindingProofRequest is created by hub-pro over machine-local IPC while it
// handles network/agent/register. Socket peer credentials prove locality;
// nonce and signature bind the active Hub connection and profile identity.
type BindingProofRequest struct {
	Version      int         `json:"version"`
	Type         MessageType `json:"type"`
	ProfileKey   string      `json:"profileKey"`
	ConnectionID string      `json:"connectionId"`
	Nonce        string      `json:"nonce"`
}

type BindingProofResponse struct {
	Version      int         `json:"version"`
	Type         MessageType `json:"type"`
	AgentKey     string      `json:"agentKey"`
	ProfileKey   string      `json:"profileKey"`
	ConnectionID string      `json:"connectionId"`
	Nonce        string      `json:"nonce"`
	Capabilities []string    `json:"capabilities"`
	IssuedAt     string      `json:"issuedAt"`
	ExpiresAt    string      `json:"expiresAt"`
	Signature    string      `json:"signature"`
}

// StatusResponse reports agent health for IPC callers.
type StatusResponse struct {
	Version    int         `json:"version"`
	Type       MessageType `json:"type"`
	AgentKey   string      `json:"agentKey"`
	Ready      bool        `json:"ready"`
	Reason     string      `json:"reason,omitempty"`
	ServerTime time.Time   `json:"serverTime"`
}

// HandlerServer is a thin Handler wrapper for direct in-process dispatch
// without a socket. Useful for tests and callers that already hold a
// connection. The socket-bound Server is in server.go.
type HandlerServer struct {
	handler Handler
}

// NewHandlerServer returns a HandlerServer backed by handler.
func NewHandlerServer(handler Handler) *HandlerServer { return &HandlerServer{handler: handler} }

// Handler exposes the underlying handler for direct testing without a socket.
func (s *HandlerServer) Handler() Handler { return s.handler }

// ErrNotImplemented marks unimplemented scaffold methods.
var ErrNotImplemented = errors.New("ipc: not implemented in scaffold")
