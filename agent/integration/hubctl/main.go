// Command hubctl is a test client for Hub Network acceptance runs. It plays the
// owner's app: it sets the hub-net-node endpoint and asks the hub's local agent
// for an invitation, the same calls Hub App makes.
//
//	hubctl -identity owner.identity key
//	hubctl -hub ws://127.0.0.1:1997 -identity owner.identity node-set ws://192.168.65.4:1964
//	hubctl -hub ws://127.0.0.1:1997 -identity owner.identity invite
//	hubctl -hub ws://127.0.0.1:1997 -identity owner.identity list
//	hubctl -hub ws://127.0.0.1:1997 -identity owner.identity approve
//	hubctl -identity owner.identity agent post net/ports/update '{"update":[{"port":8080}]}'
//	hubctl -identity owner.identity agent stream net/users
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	hubservice "github.com/v57/hub-service-go"
	"github.com/v57/hub-service-go/identity"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "hubctl: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("hubctl", flag.ContinueOnError)
	hub := flags.String("hub", "ws://127.0.0.1:1997", "hub-pro address")
	identityPath := flags.String("identity", "owner.identity", "identity file, created when missing")
	timeout := flags.Duration("timeout", 30*time.Second, "how long to wait for the hub and its agent")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() == 0 {
		return errors.New("usage: hubctl [flags] key | node-set <endpoint> | invite | list | approve | agent post|stream <path> [json]")
	}
	id, err := loadOrCreate(*identityPath)
	if err != nil {
		return err
	}
	if flags.Arg(0) == "key" {
		key, err := id.PublicKeyBase64()
		if err != nil {
			return err
		}
		fmt.Println(key)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	svc, err := hubservice.New(hubservice.Options{Address: *hub, Identity: id, Name: "hubctl"})
	if err != nil {
		return err
	}
	if err := svc.Start(); err != nil {
		return err
	}
	defer svc.Stop()

	switch flags.Arg(0) {
	case "node-set":
		if flags.NArg() != 2 {
			return errors.New("usage: hubctl node-set <endpoint>")
		}
		_, err := svc.Send("hub/net/node/set", flags.Arg(1))
		return err
	case "list":
		list, err := hubservice.OneValueTyped[any](ctx, svc, "hub/net/list", nil)
		if err != nil {
			return err
		}
		encoded, _ := json.Marshal(list)
		fmt.Println(string(encoded))
		return nil
	case "approve":
		return approvePending(ctx, svc)
	case "agent":
		// Calls the hub's local agent the way Hub App does: routed by
		// context.service to the provider on the hub's machine.
		if flags.NArg() < 3 {
			return errors.New("usage: hubctl agent post|stream <path> [json]")
		}
		var body any
		if flags.NArg() > 3 {
			if err := json.Unmarshal([]byte(flags.Arg(3)), &body); err != nil {
				return fmt.Errorf("body: %w", err)
			}
		}
		provider, err := localProvider(ctx, svc)
		if err != nil {
			return err
		}
		route := map[string]any{"service": provider}
		var value any
		switch flags.Arg(1) {
		case "post":
			value, err = svc.Send(flags.Arg(2), body, route)
		case "stream":
			value, err = hubservice.OneValueTyped[any](ctx, svc, flags.Arg(2), body, route)
		default:
			return fmt.Errorf("unknown agent call %q", flags.Arg(1))
		}
		if err != nil {
			return err
		}
		encoded, _ := json.Marshal(value)
		fmt.Println(string(encoded))
		return nil
	case "invite":
		provider, err := localProvider(ctx, svc)
		if err != nil {
			return err
		}
		code, err := hubservice.SendTyped[string](svc, "net/invite", nil, map[string]any{"service": provider})
		if err != nil {
			return err
		}
		fmt.Println("hub://join/" + code)
		return nil
	default:
		return fmt.Errorf("unknown command %q", flags.Arg(0))
	}
}

// localProvider waits for the net/invite provider running on the hub's own
// machine (hub/net/list reports it as 127.0.0.1), as the invite UI does.
func localProvider(ctx context.Context, svc *hubservice.Service) (string, error) {
	type hubNetInfo struct {
		ID      string `json:"id"`
		LocalIP string `json:"localIp"`
	}
	for {
		list, err := hubservice.OneValueTyped[[]hubNetInfo](ctx, svc, "hub/net/list", nil)
		if err == nil {
			for _, info := range list {
				if info.LocalIP == "127.0.0.1" {
					return info.ID, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("no local net/invite provider: %w", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// approvePending waits for services asking to host APIs (hub/host/pending) and
// allows every requested path, as the owner does in Hub App.
func approvePending(ctx context.Context, svc *hubservice.Service) error {
	for {
		pending, err := hubservice.OneValueTyped[map[string][]string](ctx, svc, "hub/host/pending", nil)
		if err == nil && len(pending) > 0 {
			for key, paths := range pending {
				if _, err := svc.Send("hub/host/update", map[string]any{"key": key, "allow": paths}); err != nil {
					return err
				}
				fmt.Printf("allowed %d paths for %.24s...\n", len(paths), key)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no pending services: %w", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func loadOrCreate(path string) (*identity.Identity, error) {
	if _, err := os.Stat(path); err == nil {
		return identity.Load(path)
	}
	id, err := identity.Generate()
	if err != nil {
		return nil, err
	}
	encoded, err := id.Encode()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return nil, err
	}
	return id, nil
}
