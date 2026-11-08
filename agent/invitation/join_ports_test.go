package invitation

import (
	"context"
	"errors"
	"testing"

	"github.com/v57/hub-net-node/identity"
	"github.com/v57/hub-net/enforcement"
)

// ownerBinder is a fakeBinder that answers the owner check before the bind.
type ownerBinder struct {
	fakeBinder
	owner  bool
	checks int
}

func (b *ownerBinder) IsOwner(context.Context, any, *identity.Identity) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.checks++
	return b.owner, nil
}

// noFirewall is the daemon's Admit on a device without a firewall backend.
func noFirewall(owner bool) (string, error) {
	return enforcement.JoinCheck(enforcement.ErrPlatformUnsupported, owner)
}

func joinWithoutFirewall(t *testing.T, binder *ownerBinder) (JoinResult, error, bool) {
	t.Helper()
	nodeAddress, stopNode := runJoinNodeServer(t)
	t.Cleanup(stopNode)
	inviter := runInviter(t, nodeAddress, "127.0.0.1:0")
	t.Cleanup(inviter.stop)
	code, err := CreateCode(inviter.identity, "ws://"+nodeAddress)
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	joinerID, joinerWireGuard, adapter := newJoiner(t)
	result, err := Join(context.Background(), JoinOptions{
		Code: code, Identity: joinerID, WireGuardKey: joinerWireGuard,
		Adapter: adapter, Binder: binder, ListenPort: 51820, Admit: noFirewall,
	})
	_, up := adapter.State()
	return result, err, up
}

func TestJoinSharedHubWithoutFirewallIsRefused(t *testing.T) {
	binder := &ownerBinder{fakeBinder: fakeBinder{result: BindResult{HubKey: "hub-key"}}}
	_, err, up := joinWithoutFirewall(t, binder)
	if !errors.Is(err, enforcement.ErrSharedHubWithoutFirewall) {
		t.Fatalf("Join error = %v, want the shared Hub refusal", err)
	}
	if binder.checks != 1 {
		t.Errorf("owner checks = %d, want 1", binder.checks)
	}
	if binder.callCount() != 0 {
		t.Error("the refused join still bound at the Hub")
	}
	if up {
		t.Error("temporary link left up after the refusal")
	}
}

func TestJoinOwnHubWithoutFirewallWarns(t *testing.T) {
	binder := &ownerBinder{owner: true, fakeBinder: fakeBinder{result: BindResult{HubKey: "hub-key"}}}
	result, err, up := joinWithoutFirewall(t, binder)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if result.Warning != enforcement.UnlimitedPortsWarning {
		t.Errorf("warning = %q, want the unlimited ports warning", result.Warning)
	}
	if binder.callCount() != 1 || result.HubKey != "hub-key" {
		t.Errorf("binds = %d, result = %+v", binder.callCount(), result)
	}
	if !up {
		t.Error("temporary link not left up for the session")
	}
}

// A Binder that can't tell ownership counts as a shared Hub.
func TestJoinWithoutOwnerCheckerCountsAsShared(t *testing.T) {
	nodeAddress, stopNode := runJoinNodeServer(t)
	defer stopNode()
	inviter := runInviter(t, nodeAddress, "127.0.0.1:0")
	defer inviter.stop()
	code, err := CreateCode(inviter.identity, "ws://"+nodeAddress)
	if err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	joinerID, joinerWireGuard, adapter := newJoiner(t)
	binder := &fakeBinder{}
	_, err = Join(context.Background(), JoinOptions{
		Code: code, Identity: joinerID, WireGuardKey: joinerWireGuard,
		Adapter: adapter, Binder: binder, ListenPort: 51820, Admit: noFirewall,
	})
	if !errors.Is(err, enforcement.ErrSharedHubWithoutFirewall) || binder.callCount() != 0 {
		t.Fatalf("Join error = %v, binds = %d", err, binder.callCount())
	}
}
