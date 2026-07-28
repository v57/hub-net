// Command hub-net runs the production Hub Network agent.
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

var buildVersion = "dev"

func main() {
	cfg := config.Defaults()
	stateDir := flag.String("state-dir", cfg.StateDir, "agent state directory")
	hubAddress := flag.String("hub-address", fmt.Sprint(cfg.HubAddress), "Hub WebSocket address")
	socketPath := flag.String("socket", cfg.AgentSocketPath, "local service IPC socket")
	dnsListen := flag.String("dns-listen", cfg.DNSListenAddress, "reserved-suffix DNS listen address")
	interfaceName := flag.String("interface", "hubnet0", "WireGuard interface name")
	logJSON := flag.Bool("log-json", true, "emit JSON structured logs")
	showVersion := flag.Bool("version", false, "print build version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildVersion)
		return
	}

	cfg.StateDir = *stateDir
	cfg.IdentityPath = ""
	cfg.WireGuardKeyPath = ""
	cfg.HubAddress = *hubAddress
	cfg.AgentSocketPath = *socketPath
	cfg.DNSListenAddress = *dnsListen

	agent, err := hubnet.New(hubnet.Options{
		Config:        cfg,
		Logger:        logging.New(logging.Options{Format: logFormat(*logJSON)}),
		Production:    true,
		InterfaceName: *interfaceName,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hub-net: configure agent: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := agent.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "hub-net: agent stopped: %v\n", err)
		os.Exit(1)
	}
}

func logFormat(json bool) logging.Format {
	if json {
		return logging.FormatJSON
	}
	return logging.FormatText
}
