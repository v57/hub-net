package invitation

import (
	"testing"
	"time"

	"github.com/v57/hub-net-node/identity"
	hubservice "github.com/v57/hub-service-go"
)

// Hub app H-034: a member asking the hub machine's agent for an invitation got one the hub admitted as the owner's.
// The agent holds it first, so the device that joins with it waits for an owner.
func TestHoldIsForCallersWhoArentOwners(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	code, err := CreateCode(id, "wss://v57.dev:1964")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	decoded, err := Decode(code, now)
	if err != nil {
		t.Fatal(err)
	}
	if hold, err := Hold(code, &hubservice.Caller{Key: "owner", Owner: true}, now); err != nil || hold != nil {
		t.Fatalf("an owner's invitation is held: %v, %v", hold, err)
	}
	member := &hubservice.Caller{Key: "member", Device: &hubservice.CallerDevice{ID: "member-device", Name: "iPhone"}}
	hold, err := Hold(code, member, now)
	if err != nil || hold == nil {
		t.Fatalf("a member's invitation isn't held: %v", err)
	}
	if hold["replayId"] != decoded.Envelope.TokenID || len(decoded.Envelope.TokenID) != 43 {
		t.Fatalf("replay id %v, want %s", hold["replayId"], decoded.Envelope.TokenID)
	}
	if hold["expiresAt"] != decoded.Envelope.ExpiresAt {
		t.Fatalf("expiry %v, want %s", hold["expiresAt"], decoded.Envelope.ExpiresAt)
	}
	by := hold["by"].(map[string]any)
	if by["key"] != "member" || by["device"] != "member-device" || by["name"] != "iPhone" {
		t.Fatalf("by %v", by)
	}
	if hold, err := Hold(code, nil, now); err != nil || hold == nil {
		t.Fatalf("a caller the hub didn't name isn't held: %v", err)
	}
}
