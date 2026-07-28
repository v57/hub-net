package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNewJSONDefaults(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Writer: &buf})
	logger.Info("hello", slog.String("k", "v"))
	out := buf.String()
	if !strings.Contains(out, "\"msg\"") {
		t.Fatalf("expected JSON output, got %s", out)
	}
	if !strings.Contains(out, "\"component\"") {
		// component not present here; that's fine, this is the base logger.
	}
	if !strings.Contains(out, "\"k\":\"v\"") {
		t.Fatalf("expected attribute k=v in %s", out)
	}
}

func TestNewTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(Options{Writer: &buf, Format: FormatText})
	logger.Info("hello")
	out := buf.String()
	if !strings.Contains(out, "msg=hello") {
		t.Fatalf("expected text format, got %s", out)
	}
}

func TestComponentAddsTag(t *testing.T) {
	var buf bytes.Buffer
	base := New(Options{Writer: &buf})
	named := Component(base, "wireguard")
	named.Info("up")
	out := buf.String()
	if !strings.Contains(out, "\"component\":\"wireguard\"") {
		t.Fatalf("expected component tag in %s", out)
	}
}

func TestComponentHandlesNilBase(t *testing.T) {
	named := Component(nil, "ipc")
	if named == nil {
		t.Fatalf("Component returned nil")
	}
}
