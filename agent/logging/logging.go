// Package logging provides structured logging for the hub-net agent.
//
// The agent uses the standard log/slog package. This package exposes a small
// helper layer so callers can request a logger pre-tagged with a component
// name (for example "wireguard" or "ipc") without re-passing the tag at every
// call site. Levels are taken from the configured slog.Handler so log volume
// stays controllable across the agent, IPC server, and platform adapters.
package logging

import (
	"io"
	"log/slog"
	"os"
)

// DefaultLevel is the slog level used when Options.Level is unset. Info keeps
// routine agent activity visible during bring-up without requiring DEBUG.
const DefaultLevel = slog.LevelInfo

// Format selects the structured logging text representation.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Options configures the agent logger. Zero values resolve to documented
// defaults: JSON to stderr, Info level.
type Options struct {
	// Writer is the destination. Defaults to os.Stderr.
	Writer io.Writer
	// Format is FormatText or FormatJSON. Defaults to FormatJSON, which keeps
	// log lines machine-parseable for diagnostics tooling.
	Format Format
	// Level is the slog level. Defaults to DefaultLevel.
	Level slog.Level
	// AddSource records the call site of each log statement.
	AddSource bool
}

// New constructs a *slog.Logger from options.
func New(options Options) *slog.Logger {
	writer := options.Writer
	if writer == nil {
		writer = os.Stderr
	}
	format := options.Format
	if format == "" {
		format = FormatJSON
	}
	level := options.Level
	if level == 0 {
		level = DefaultLevel
	}
	handlerOptions := &slog.HandlerOptions{
		Level:     level,
		AddSource: options.AddSource,
	}
	var handler slog.Handler
	if format == FormatText {
		handler = slog.NewTextHandler(writer, handlerOptions)
	} else {
		handler = slog.NewJSONHandler(writer, handlerOptions)
	}
	return slog.New(handler)
}

// Component returns a logger tagged with the given component name. The tag is
// recorded under the key "component" so platform adapters and subsystems can
// be filtered without per-call attributes.
func Component(base *slog.Logger, name string) *slog.Logger {
	if base == nil {
		return slog.Default().With(slog.String("component", name))
	}
	return base.With(slog.String("component", name))
}
