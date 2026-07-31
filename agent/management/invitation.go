package management

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/v57/hub-net/invitation"
	"github.com/v57/hub-net/membership"
)

// IdentityFactory creates fresh private join identity. Staged invitation
// storage preserves it across retries.
type IdentityFactory func() (invitation.JoinIdentity, error)

// RecordFactory translates committed invitation state into one complete
// daemon membership record and its user-facing virtual endpoint.
type RecordFactory func(invitation.Decoded, invitation.Membership) (JoinResult, error)

// InvitationJoinFunc bridges HN-823 staged joining into daemon management.
// Invitation token ID is stable transaction identity, making repeated CLI
// delivery resume or return the same committed membership.
func InvitationJoinFunc(joiner invitation.Joiner, identity IdentityFactory, record RecordFactory) JoinFunc {
	return func(ctx context.Context, input string) (JoinResult, error) {
		decoded, err := invitation.Decode(input, joinNow(joiner))
		if err != nil {
			return JoinResult{}, err
		}
		if identity == nil || record == nil {
			return JoinResult{}, errors.New("management: invitation join dependencies required")
		}
		keys, err := identity()
		if err != nil {
			return JoinResult{}, fmt.Errorf("management: create join identity: %w", err)
		}
		joined, err := joiner.Join(ctx, input, decoded.Envelope.TokenID, keys)
		if err != nil {
			return JoinResult{}, err
		}
		result, err := record(decoded, joined)
		if err != nil {
			return JoinResult{}, fmt.Errorf("management: build membership: %w", err)
		}
		if result.Record.ID != joined.ID || result.Record.Alias != joined.Alias {
			return JoinResult{}, errors.New("management: membership record does not match committed join")
		}
		return result, nil
	}
}

func joinNow(joiner invitation.Joiner) time.Time {
	if joiner.Now != nil {
		return joiner.Now()
	}
	return time.Now()
}

// DefaultRecord builds common persisted fields. Platform join wiring supplies
// Hub address, network identity, interface, and translated allocation.
func DefaultRecord(
	joined invitation.Membership,
	header string,
	hubAddress json.RawMessage,
	networkID, nodeURL, interfaceName, translatedIPv4, translatedIPv6 string,
	virtualHost string,
) (JoinResult, error) {
	ipv4, err := netip.ParsePrefix(translatedIPv4)
	if err != nil {
		return JoinResult{}, errors.New("management: invalid translated IPv4 prefix")
	}
	virtualIP := ipv4.Addr().Next().String()
	return JoinResult{
		Record: membership.Record{
			Version: membership.Version, ID: joined.ID, Alias: joined.Alias, Header: header,
			HubAddress: hubAddress, NetworkID: networkID, NodeURL: nodeURL,
			InterfaceName: interfaceName, TranslatedIPv4: translatedIPv4,
			TranslatedIPv6: translatedIPv6, GatewayAllowed: false,
		},
		VirtualHost: virtualHost,
		VirtualIP:   virtualIP,
	}, nil
}

func RandomTransactionIdentity() (invitation.JoinIdentity, error) {
	values := make([]string, 3)
	for index := range values {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return invitation.JoinIdentity{}, err
		}
		values[index] = base64.StdEncoding.EncodeToString(raw)
	}
	return invitation.JoinIdentity{
		ProfileKey: values[0], AgentKey: values[1], WireGuardKey: values[2],
	}, nil
}
