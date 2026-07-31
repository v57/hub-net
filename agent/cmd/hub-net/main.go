// Command hub-net runs daemon or sends one command to its local socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	hubnet "github.com/v57/hub-net"
	"github.com/v57/hub-net/config"
	"github.com/v57/hub-net/logging"
	"github.com/v57/hub-net/management"
	"github.com/v57/hub-net/membership"
	"github.com/v57/hub-net/publications"
	"github.com/v57/hub-net/supervisor"
)

var buildVersion = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "hub-net: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg := config.Defaults()
	flags := flag.NewFlagSet("hub-net", flag.ContinueOnError)
	stateDir := flags.String("state-dir", cfg.StateDir, "agent state directory")
	socketPath := flags.String("socket", "", "daemon command IPC socket")
	dnsListen := flags.String("dns-listen", cfg.DNSListenAddress, "reserved-suffix DNS listen address")
	logJSON := flags.Bool("log-json", true, "emit JSON structured logs")
	showVersion := flags.Bool("version", false, "print build version and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(buildVersion)
		return nil
	}
	if *socketPath == "" {
		*socketPath = filepath.Join(*stateDir, "command.sock")
	}
	if flags.NArg() > 0 {
		request, err := management.ParseCommand(flags.Args())
		if err != nil {
			return err
		}
		response, err := management.NewClient(*socketPath).Execute(context.Background(), request)
		if err != nil {
			return err
		}
		switch request.Command {
		case "join":
			fmt.Println(management.FormatJoin(*response.Joined))
		case "list":
			if output := management.FormatList(response.Items); output != "" {
				fmt.Println(output)
			}
		}
		return nil
	}

	store, err := membership.Open(*stateDir)
	if err != nil {
		return err
	}
	logger := logging.New(logging.Options{Format: logFormat(*logJSON)})
	daemon, err := hubnet.NewDaemon(func(member supervisor.Membership) (hubnet.Options, error) {
		sessionConfig := cfg
		sessionConfig.StateDir = member.StateDir
		sessionConfig.IdentityPath = member.IdentityPath
		sessionConfig.WireGuardKeyPath = member.WireGuardKeyPath
		sessionConfig.HubAddress = member.HubAddress
		sessionConfig.AgentSocketPath = filepath.Join(member.StateDir, "service.sock")
		sessionConfig.DNSListenAddress = *dnsListen
		publicationsPath := member.PublicationsPath
		if publicationsPath == "" {
			publicationsPath = filepath.Join(member.StateDir, "publications.json")
		}
		shares, err := publications.Load(publicationsPath)
		if err != nil {
			return hubnet.Options{}, err
		}
		return hubnet.Options{
			Config: sessionConfig, Logger: logger, Production: true,
			InterfaceName:  member.InterfaceName,
			InitialShares:  shares,
			GatewayAllowed: member.GatewayAllowed,
		}, nil
	})
	if err != nil {
		return err
	}
	service, err := management.NewService(daemon, store, nil)
	if err != nil {
		return err
	}
	server, err := management.NewServer(*socketPath, service)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	daemonDone := make(chan error, 1)
	go func() { daemonDone <- daemon.Run(ctx) }()
	if err := daemon.WaitRunning(ctx); err != nil {
		return err
	}
	if _, err := daemon.Restore(store); err != nil {
		return err
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(ctx) }()
	select {
	case err := <-daemonDone:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case err := <-serverDone:
		daemon.Shutdown()
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

func logFormat(json bool) logging.Format {
	if json {
		return logging.FormatJSON
	}
	return logging.FormatText
}
