package invitation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"

	"github.com/v57/channel-go/channelgo"
	hubservice "github.com/v57/hub-service-go"
	"github.com/v57/hub-service-go/identity"
	"github.com/v57/hub-service-go/service"
)

const InvitePath = "net/invite"

// inviteOnlineWait bounds how long net/invite waits for the agent's node
// registration, e.g. right after the agent connected.
const inviteOnlineWait = 10 * time.Second

// RegisterInviteService exposes agent-owned compact invitation creation.
// online reports whether the agent is registered with hub-net-node as an
// inviter; the node rejects joins while it is not, so no code is issued then.
func RegisterInviteService(svc *hubservice.Service, id *identity.Identity, endpoint func() string, online func() bool) error {
	if svc == nil || id == nil || online == nil {
		return fmt.Errorf("invitation: service, identity and online state required")
	}
	svc.Post(InvitePath, func(channelgo.Body) (any, error) {
		for deadline := time.Now().Add(inviteOnlineWait); !online(); {
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("invitation: not registered with hub-net-node %s", endpoint())
			}
			time.Sleep(100 * time.Millisecond)
		}
		return CreateCode(id, endpoint())
	}, service.Settings{Permissions: &service.Permissions{
		Group: "Hub Network", Name: "Invite to Hub Net",
	}})
	return nil
}

// CreateCode returns publicKey.expires.nonce?query/signature.
func CreateCode(id *identity.Identity, endpoint string) (string, error) {
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("invitation: nonce: %w", err)
	}
	var expires [4]byte
	binary.BigEndian.PutUint32(expires[:], uint32(time.Now().Add(7*24*time.Hour).Unix()))
	publicKey := base64.RawURLEncoding.EncodeToString(id.PublicKey())
	payload := publicKey + "." + base64.RawURLEncoding.EncodeToString(expires[:]) + "." + base64.RawURLEncoding.EncodeToString(nonce[:])
	if endpoint != "" && endpoint != "hub.v57.dev/node" {
		payload += "?e=" + url.QueryEscape(endpoint)
	}
	signed := ed25519.Sign(id.PrivateKey(), []byte(payload))
	signature := base64.RawURLEncoding.EncodeToString(signed)
	return payload + "/" + signature, nil
}
