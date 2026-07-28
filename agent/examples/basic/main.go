// Command hubnet runs the local Hub Network agent.
//
// It is intentionally a thin wrapper around hubnet.Agent. Real platform
// Production startup uses the real platform adapter and fails before Hub
// registration when required networking privileges are unavailable.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	hubnet "github.com/v57/hub-net"
	"github.com/v57/hub-net/config"
	"github.com/v57/hub-net/logging"
)

func main() {
	stateDir := flag.String("state-dir", config.DefaultStateDir(), "agent state directory")
	hubPort := flag.Int("hub-port", config.DefaultHubPort, "Hub WebSocket port")
	logJSON := flag.Bool("log-json", true, "emit JSON structured logs")
	flag.Parse()

	cfg := config.Defaults()
	cfg.StateDir = *stateDir
	cfg.HubAddress = *hubPort

	agent, err := hubnet.New(hubnet.Options{
		Config:     cfg,
		Logger:     logging.New(logging.Options{Format: format(*logJSON)}),
		Production: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hub-net: configure agent: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := agent.Run(ctx); err != nil && !isContextDone(ctx) {
		fmt.Fprintf(os.Stderr, "hub-net: agent stopped: %v\n", err)
		os.Exit(1)
	}
}

func format(json bool) logging.Format {
	if json {
		return logging.FormatJSON
	}
	return logging.FormatText
}

func isContextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
