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

// RegisterInviteService exposes agent-owned compact invitation creation.
func RegisterInviteService(svc *hubservice.Service, id *identity.Identity, endpoint func() string) error {
	if svc == nil || id == nil {
		return fmt.Errorf("invitation: service and identity required")
	}
	svc.Post(InvitePath, func(channelgo.Body) (any, error) {
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
