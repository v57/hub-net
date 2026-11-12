package invitation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/v57/hub-net-node/identity"
	"github.com/v57/hub-net/hubconn"
	hubservice "github.com/v57/hub-service-go"
)

const InvitePath = "net/invite"

// inviteOnlineWait bounds how long net/invite waits for the agent's node
// registration, e.g. right after the agent connected.
const inviteOnlineWait = 10 * time.Second

// HoldPath keeps an invitation's joiner waiting for an owner (protocol.md section 10)
const HoldPath = "hub/net/invitations/hold"

// RegisterInviteService exposes agent-owned compact invitation creation.
// online reports whether the agent is registered with hub-net-node as an
// inviter; the node rejects joins while it is not, so no code is issued then.
// A code made for a caller who isn't an owner is held first (HoldPath), so the
// device that joins with it waits for an owner although this agent signed it
// (security decisions 1.0, Hub 4; Hub app H-034); without the hold it isn't
// handed out.
func RegisterInviteService(svc *hubconn.Service, id *identity.Identity, endpoint func() string, online func() bool) error {
	if svc == nil || id == nil || online == nil {
		return fmt.Errorf("invitation: service, identity and online state required")
	}
	svc.PostRequest(InvitePath, func(request hubservice.Request) (any, error) {
		if endpoint() == "" {
			return nil, errNoNode
		}
		for deadline := time.Now().Add(inviteOnlineWait); !online(); {
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("invitation: not registered with hub-net-node %s", endpoint())
			}
			time.Sleep(100 * time.Millisecond)
		}
		code, err := CreateCode(id, endpoint())
		if err != nil {
			return nil, err
		}
		hold, err := Hold(code, request.Caller, time.Now())
		if err != nil {
			return nil, err
		}
		if hold != nil {
			if _, err := svc.Send(HoldPath, hold); err != nil {
				return nil, fmt.Errorf("invitation: the hub couldn't keep this invitation waiting for an owner's approval, so it wasn't made: %w", err)
			}
		}
		return code, nil
	}, hubconn.Settings{Permissions: &hubconn.Permissions{
		Group: "Hub Network", Name: "Invite to Hub Net",
	}})
	return nil
}

// Hold is what InvitePath holds for a code it made for caller: nothing for an
// owner, else the invitation's replay id, expiry and who asked for it. A hub
// that names no caller is held too: it's who the hub can't vouch for.
func Hold(code string, caller *hubservice.Caller, now time.Time) (map[string]any, error) {
	if caller != nil && caller.Owner {
		return nil, nil
	}
	decoded, err := Decode(code, now)
	if err != nil {
		return nil, fmt.Errorf("invitation: %w", err)
	}
	by := map[string]any{}
	if caller != nil {
		if caller.Key != "" {
			by["key"] = caller.Key
		}
		if caller.Device != nil {
			by["device"] = caller.Device.ID
			if caller.Device.Name != "" {
				by["name"] = caller.Device.Name
			}
		}
	}
	return map[string]any{"replayId": decoded.Envelope.TokenID, "expiresAt": decoded.Envelope.ExpiresAt, "by": by}, nil
}

// errNoNode refuses invitations while no hub-net-node is set (hub/net/node).
var errNoNode = errors.New("invitation: no Hub Network node is set; set one with hub/net/node/set")

// CreateCode returns publicKey.expires.nonce?e=node/signature. endpoint (the
// hub-net-node) is required: there is no built-in node.
func CreateCode(id *identity.Identity, endpoint string) (string, error) {
	if endpoint == "" {
		return "", errNoNode
	}
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("invitation: nonce: %w", err)
	}
	var expires [4]byte
	binary.BigEndian.PutUint32(expires[:], uint32(time.Now().Add(7*24*time.Hour).Unix()))
	publicKey := base64.RawURLEncoding.EncodeToString(id.PublicKey())
	payload := publicKey + "." + base64.RawURLEncoding.EncodeToString(expires[:]) + "." + base64.RawURLEncoding.EncodeToString(nonce[:])
	payload += "?e=" + url.QueryEscape(endpoint)
	signed := ed25519.Sign(id.PrivateKey(), []byte(payload))
	signature := base64.RawURLEncoding.EncodeToString(signed)
	return payload + "/" + signature, nil
}
