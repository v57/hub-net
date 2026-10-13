package network

import (
	"bytes"
	"sort"

	protocol "github.com/v57/hub-net-node/models"
)

// challengeRequest is the body of the local-agent /challenge request.
type challengeRequest struct {
	ServiceKey string               `json:"serviceKey"`
	ShareName  string               `json:"shareName"`
	Protocol   string               `json:"protocol"`
	Target     protocol.LocalTarget `json:"target"`
}

// byteReader wraps encoded bytes as an io.Reader for http.NewRequest.
func byteReader(data []byte) *bytes.Reader {
	return bytes.NewReader(data)
}

// optionalDetail prefixes a non-empty detail string with ": ".
func optionalDetail(detail string) string {
	if detail == "" {
		return ""
	}
	return ": " + detail
}

// sortShares orders shares by name so the declared set is stable across calls.
func sortShares(shares []Share) {
	sort.Slice(shares, func(i, j int) bool {
		return shares[i].Name < shares[j].Name
	})
}
