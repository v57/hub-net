//go:build linux

package platform

import (
	"strings"
	"testing"
)

func TestEffectiveCapabilities(t *testing.T) {
	got, err := effectiveCapabilities("Name:\thub-net\nCapEff:\t0000000000003000\n")
	if err != nil {
		t.Fatalf("effectiveCapabilities: %v", err)
	}
	want := uint64(1<<capNetAdmin | 1<<capNetRaw)
	if got != want {
		t.Fatalf("capabilities = %#x, want %#x", got, want)
	}
}

func TestEffectiveCapabilitiesRejectsMissingField(t *testing.T) {
	if _, err := effectiveCapabilities("Name:\thub-net\n"); err == nil {
		t.Fatal("expected missing CapEff error")
	}
}

func TestMissingCapabilitiesAreNamedIndividually(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   string
	}{
		{"net admin", "CapEff:\t0000000000002000\n", "CAP_NET_ADMIN"},
		{"net raw", "CapEff:\t0000000000001000\n", "CAP_NET_RAW"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			effective, err := effectiveCapabilities(tt.status)
			if err != nil {
				t.Fatalf("effectiveCapabilities: %v", err)
			}
			got := strings.Join(missingCapabilities(effective), ", ")
			if got != tt.want {
				t.Fatalf("missing = %q, want %q", got, tt.want)
			}
		})
	}
}
