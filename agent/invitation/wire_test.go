package invitation_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/v57/hub-net/invitation"
)

func TestWireFixtures(t *testing.T) {
	fixturesDir := filepath.Join("testdata", "native-join")

	t.Run("header.json", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixturesDir, "header.json"))
		if err != nil {
			t.Fatal(err)
		}
		var header invitation.HubHeader
		if err := json.Unmarshal(data, &header); err != nil {
			t.Fatal(err)
		}
		if header.Name != "Acme Hub" {
			t.Errorf("unexpected parsed fields: %+v", header)
		}
	})

	t.Run("error.json", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixturesDir, "error.json"))
		if err != nil {
			t.Fatal(err)
		}
		var netErr invitation.NetworkError
		if err := json.Unmarshal(data, &netErr); err != nil {
			t.Fatal(err)
		}
		if netErr.Version != 1 || netErr.Code == "" {
			t.Errorf("unexpected parsed fields: %+v", netErr)
		}
		if netErr.Details["field"] != "tokenId" {
			t.Errorf("unexpected error details: %+v", netErr.Details)
		}
	})

	t.Run("progress.json", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixturesDir, "progress.json"))
		if err != nil {
			t.Fatal(err)
		}
		var progress invitation.AppleBootstrapStatus
		if err := json.Unmarshal(data, &progress); err != nil {
			t.Fatal(err)
		}
		if progress.Version != 1 || progress.State == "" {
			t.Errorf("unexpected parsed fields: %+v", progress)
		}
	})

	t.Run("agent-profile.json", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(fixturesDir, "agent-profile.json"))
		if err != nil {
			t.Fatal(err)
		}
		var profile invitation.AgentProfile
		if err := json.Unmarshal(data, &profile); err != nil {
			t.Fatal(err)
		}
		if profile.Version != 1 || profile.Key == "" {
			t.Errorf("unexpected parsed fields: %+v", profile)
		}
	})
}
