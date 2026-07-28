package ipc

import (
	"errors"
	"testing"
	"time"
)

type stubHandler struct {
	challenge ChallengeResponse
	attest    AttestResponse
	status    StatusResponse
	err       error
}

func (s *stubHandler) Challenge(req ChallengeRequest) (ChallengeResponse, error) {
	return s.challenge, s.err
}

func (s *stubHandler) Attest(req AttestRequest) (AttestResponse, error) {
	return s.attest, s.err
}

func (s *stubHandler) Status(req StatusRequest) (StatusResponse, error) {
	return s.status, s.err
}

func TestNewHandlerServerWrapsHandler(t *testing.T) {
	h := &stubHandler{status: StatusResponse{Ready: true, ServerTime: time.Now()}}
	server := NewHandlerServer(h)
	if server.Handler() != h {
		t.Fatalf("Handler mismatch")
	}
}

func TestHandlerServerDispatch(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	h := &stubHandler{
		challenge: ChallengeResponse{Nonce: "n", AgentKey: "ak", IssuedAt: now},
		status:    StatusResponse{Ready: true, AgentKey: "ak", ServerTime: now},
		err:       nil,
	}
	server := NewHandlerServer(h)
	challenge, err := server.Handler().Challenge(ChallengeRequest{ServiceKey: "sk"})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if challenge.Nonce != "n" {
		t.Fatalf("nonce = %s", challenge.Nonce)
	}
	status, err := server.Handler().Status(StatusRequest{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Ready {
		t.Fatalf("status not ready")
	}
}

func TestErrNotImplementedIsSentinel(t *testing.T) {
	if !errors.Is(ErrNotImplemented, ErrNotImplemented) {
		t.Fatalf("ErrNotImplemented not comparable")
	}
}
