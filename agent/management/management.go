// Package management implements serialized local daemon commands.
package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	hubnet "github.com/v57/hub-net"
	"github.com/v57/hub-net/membership"
	"github.com/v57/hub-net/publications"
	"github.com/v57/hub-net/supervisor"
)

const (
	Version         = 1
	MaxRequestBytes = 64 * 1024
)

type JoinResult struct {
	Record      membership.Record `json:"record"`
	VirtualHost string            `json:"virtualHost"`
	VirtualIP   string            `json:"virtualIp"`
}

type JoinFunc func(context.Context, string) (JoinResult, error)

// LocalFunc creates the membership for the hub running on this machine from
// its address.
type LocalFunc func(context.Context, string) (membership.Record, error)

// DefaultLocalHubAddress is the hub-server address `hub-net local` uses when none
// is given.
const DefaultLocalHubAddress = "ws://127.0.0.1:1997"

type Service struct {
	mu     sync.Mutex
	daemon Daemon
	store  *membership.Store
	join   JoinFunc
	local  LocalFunc
}

type Daemon interface {
	Add(supervisor.Membership) error
	Remove(string) error
	List() []hubnet.HubListItem
	OpenShare(context.Context, string, publications.Entry) error
	CloseShare(context.Context, string, string) error
	SetGateway(context.Context, string, bool) error
}

func NewService(daemon Daemon, store *membership.Store, join JoinFunc, local LocalFunc) (*Service, error) {
	if daemon == nil || store == nil {
		return nil, errors.New("management: daemon and membership store required")
	}
	return &Service{daemon: daemon, store: store, join: join, local: local}, nil
}

type Request struct {
	Version int    `json:"version"`
	Command string `json:"command"`
	Code    string `json:"code,omitempty"`
	Address string `json:"address,omitempty"`
	Alias   string `json:"alias,omitempty"`
	Port    uint16 `json:"port,omitempty"`
}

type Response struct {
	Version int                  `json:"version"`
	Joined  *JoinResult          `json:"joined,omitempty"`
	Items   []hubnet.HubListItem `json:"items,omitempty"`
	Error   string               `json:"error,omitempty"`
}

func (s *Service) Execute(ctx context.Context, request Request) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	response := Response{Version: Version}
	if request.Version != Version {
		response.Error = "unsupported command version"
		return response
	}
	switch request.Command {
	case "join":
		if request.Code == "" {
			response.Error = "join code required"
			break
		}
		if s.join == nil {
			response.Error = "join unavailable"
			break
		}
		result, err := s.join(ctx, request.Code)
		if err != nil {
			response.Error = err.Error()
			break
		}
		if err := s.store.Stage(result.Record); err == nil {
			var stored membership.Stored
			stored, err = s.store.Commit(result.Record.ID)
			if err == nil {
				err = s.daemon.Add(toSupervisor(stored))
			}
		}
		if err != nil {
			response.Error = err.Error()
			break
		}
		response.Joined = &result
	case "local":
		if s.local == nil {
			response.Error = "local hub unavailable"
			break
		}
		records, _, err := s.store.Load()
		if err == nil {
			for _, stored := range records {
				if stored.Record.Local {
					err = fmt.Errorf("this machine already serves hub %q", stored.Record.Alias)
				}
			}
		}
		var record membership.Record
		if err == nil {
			record, err = s.local(ctx, request.Address)
		}
		if err == nil {
			err = s.store.Stage(record)
		}
		var stored membership.Stored
		if err == nil {
			stored, err = s.store.Commit(record.ID)
		}
		if err == nil {
			err = s.daemon.Add(toSupervisor(stored))
		}
		if err != nil {
			response.Error = err.Error()
			break
		}
		response.Joined = &JoinResult{Record: record}
	case "leave":
		stored, found, err := s.store.FindAlias(request.Alias)
		if err == nil && !found {
			break
		}
		if err == nil {
			err = s.daemon.Remove(stored.Record.ID)
		}
		if err == nil {
			err = s.store.Remove(stored.Record.ID)
		}
		if err != nil {
			response.Error = err.Error()
		}
	case "removeAll":
		for _, item := range s.daemon.List() {
			if err := s.daemon.Remove(item.ID); err != nil {
				response.Error = err.Error()
				return response
			}
		}
		if err := s.store.RemoveAll(); err != nil {
			response.Error = err.Error()
		}
	case "list":
		response.Items = s.daemon.List()
		// Paused memberships have no session; list them from the store
		if records, _, err := s.store.Load(); err == nil {
			for _, stored := range records {
				if stored.Record.Paused {
					response.Items = append(response.Items, pausedItem(stored.Record))
				}
			}
		}
	case "pause", "resume":
		if request.Alias == "" {
			response.Error = "hub name required"
			break
		}
		if err := s.setPaused(request.Command == "pause", request.Alias); err != nil {
			response.Error = err.Error()
		}
	case "open", "close":
		if request.Port == 0 || request.Alias == "" {
			response.Error = "port and hub name required"
			break
		}
		if err := s.mutatePort(ctx, request.Command, request.Port, request.Alias); err != nil {
			response.Error = err.Error()
		}
	case "vpnAllow", "vpnRemove":
		if request.Alias == "" {
			response.Error = "hub name required"
			break
		}
		if err := s.mutateGateway(ctx, request.Command == "vpnAllow", request.Alias); err != nil {
			response.Error = err.Error()
		}
	default:
		response.Error = "unknown command"
	}
	return response
}

func toSupervisor(stored membership.Stored) supervisor.Membership {
	var address any
	_ = json.Unmarshal(stored.Record.HubAddress, &address)
	return supervisor.Membership{
		ID: stored.Record.ID, Alias: stored.Record.Alias, Header: stored.Record.Header,
		HubAddress: address, NodeURL: stored.Record.NodeURL,
		TranslatedIPv4: stored.Record.TranslatedIPv4, TranslatedIPv6: stored.Record.TranslatedIPv6,
		StateDir: stored.StateDir, IdentityPath: stored.IdentityPath,
		WireGuardKeyPath: stored.WireGuardKeyPath, InterfaceName: stored.Record.InterfaceName,
		PublicationsPath: stored.Record.PublicationsPath,
		GatewayAllowed:   stored.Record.GatewayAllowed,
		Local:            stored.Record.Local,
		OverlayIPv4:      stored.Record.CanonicalIPv4,
		OverlayIPv6:      stored.Record.CanonicalIPv6,
	}
}

// setPaused stops a membership's session and keeps the membership (pause), or
// starts it again (resume). Both are idempotent.
func (s *Service) setPaused(paused bool, alias string) error {
	stored, found, err := s.store.FindAlias(alias)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("hub %q not found", alias)
	}
	if stored.Record.Paused == paused {
		return nil
	}
	if paused {
		if err := s.daemon.Remove(stored.Record.ID); err != nil {
			return err
		}
		_, err = s.store.UpdatePaused(stored.Record.ID, true)
		return err
	}
	stored, err = s.store.UpdatePaused(stored.Record.ID, false)
	if err != nil {
		return err
	}
	if err := s.daemon.Add(toSupervisor(stored)); err != nil {
		_, rollbackErr := s.store.UpdatePaused(stored.Record.ID, true)
		return errors.Join(err, rollbackErr)
	}
	return nil
}

func pausedItem(record membership.Record) hubnet.HubListItem {
	var address string
	_ = json.Unmarshal(record.HubAddress, &address)
	return hubnet.HubListItem{
		ID: record.ID, Alias: record.Alias, Header: record.Header, Status: supervisor.StatusPaused,
		NodeURL: record.NodeURL, GatewayAllowed: record.GatewayAllowed,
		OverlayIPv4: record.CanonicalIPv4, OverlayIPv6: record.CanonicalIPv6, HubAddress: address,
	}
}

func (s *Service) mutateGateway(ctx context.Context, allowed bool, alias string) error {
	stored, found, err := s.store.FindAlias(alias)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("hub %q not found", alias)
	}
	if stored.Record.GatewayAllowed == allowed {
		return nil
	}
	if _, err := s.store.UpdateGateway(stored.Record.ID, allowed); err != nil {
		return err
	}
	if err := s.daemon.SetGateway(ctx, stored.Record.ID, allowed); err != nil {
		_, rollbackErr := s.store.UpdateGateway(stored.Record.ID, !allowed)
		return errors.Join(err, rollbackErr)
	}
	return nil
}

func (s *Service) mutatePort(ctx context.Context, command string, port uint16, alias string) error {
	stored, found, err := s.store.FindAlias(alias)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("hub %q not found", alias)
	}
	path := stored.Record.PublicationsPath
	if path == "" {
		path = filepath.Join(stored.StateDir, "publications.json")
	}
	previous, err := publications.Load(path)
	if err != nil {
		return err
	}
	names := []string{shareName(port, "tcp"), shareName(port, "udp")}
	desired := without(previous, names...)
	if command == "open" {
		desired = append(desired,
			publications.Entry{Name: names[0], Protocol: "tcp", Host: "127.0.0.1", Port: port},
			publications.Entry{Name: names[1], Protocol: "udp", Host: "127.0.0.1", Port: port})
	}
	if sameEntries(previous, desired) {
		return nil
	}
	if err := publications.Save(path, desired); err != nil {
		return err
	}
	rollback := func(cause error) error {
		return errors.Join(cause, publications.Save(path, previous))
	}
	if command == "open" {
		opened := make([]publications.Entry, 0, 2)
		for _, entry := range desired {
			if entry.Port != port {
				continue
			}
			if err := s.daemon.OpenShare(ctx, stored.Record.ID, entry); err != nil {
				for i := len(opened) - 1; i >= 0; i-- {
					_ = s.daemon.CloseShare(ctx, stored.Record.ID, opened[i].Name)
				}
				return rollback(err)
			}
			opened = append(opened, entry)
		}
		return nil
	}
	closed := make([]publications.Entry, 0, 2)
	for _, entry := range previous {
		if entry.Port != port {
			continue
		}
		if err := s.daemon.CloseShare(ctx, stored.Record.ID, entry.Name); err != nil {
			for _, restore := range closed {
				_ = s.daemon.OpenShare(ctx, stored.Record.ID, restore)
			}
			return rollback(err)
		}
		closed = append(closed, entry)
	}
	return nil
}

func shareName(port uint16, protocol string) string {
	return "port-" + strconv.Itoa(int(port)) + "-" + protocol
}

func without(entries []publications.Entry, names ...string) []publications.Entry {
	remove := make(map[string]struct{}, len(names))
	for _, name := range names {
		remove[name] = struct{}{}
	}
	result := make([]publications.Entry, 0, len(entries))
	for _, entry := range entries {
		if _, found := remove[entry.Name]; !found {
			result = append(result, entry)
		}
	}
	return result
}

func sameEntries(a, b []publications.Entry) bool {
	rawA, _ := json.Marshal(a)
	rawB, _ := json.Marshal(b)
	return bytes.Equal(rawA, rawB)
}

type Server struct {
	path     string
	service  *Service
	listener net.Listener
	http     *http.Server
}

func NewServer(path string, service *Service) (*Server, error) {
	if path == "" || service == nil {
		return nil, errors.New("management: socket path and service required")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, err
	}
	server := &Server{path: path, service: service, listener: listener}
	server.http = &http.Server{
		Handler:           http.HandlerFunc(server.handle),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      2 * time.Minute,
	}
	return server, nil
}

// ShareWithGroup opens the command socket to a local group: owner and group
// may read and write it (0660). A desktop app run by a member of the group
// (Hub on Linux) then sends join, leave and list itself. The socket's
// directory must let the group through.
func (s *Server) ShareWithGroup(name string) error {
	group, err := user.LookupGroup(name)
	if err != nil {
		return fmt.Errorf("management: socket group %q: %w", name, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return fmt.Errorf("management: socket group %q: %w", name, err)
	}
	if err := os.Chown(s.path, -1, gid); err != nil {
		return err
	}
	return os.Chmod(s.path, 0o660)
}

func (s *Server) Serve(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- s.http.Serve(s.listener) }()
	select {
	case <-ctx.Done():
		_ = s.Close(context.Background())
		return ctx.Err()
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) Close(ctx context.Context) error {
	err := s.http.Shutdown(ctx)
	removeErr := os.Remove(s.path)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(err, removeErr)
}

func (s *Server) handle(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != "/v1/command" {
		http.NotFound(writer, request)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, MaxRequestBytes+1))
	if err != nil || len(raw) > MaxRequestBytes {
		writeJSON(writer, http.StatusBadRequest, Response{Version: Version, Error: "invalid request"})
		return
	}
	var command Request
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		writeJSON(writer, http.StatusBadRequest, Response{Version: Version, Error: "invalid request"})
		return
	}
	response := s.service.Execute(request.Context(), command)
	status := http.StatusOK
	if response.Error != "" {
		status = http.StatusBadRequest
	}
	writeJSON(writer, status, response)
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

type Client struct {
	http *http.Client
}

func NewClient(socketPath string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	}}
	return &Client{http: &http.Client{Transport: transport, Timeout: 3 * time.Minute}}
}

func (c *Client) Execute(ctx context.Context, request Request) (Response, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return Response{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/command", bytes.NewReader(raw))
	if err != nil {
		return Response{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpResponse, err := c.http.Do(httpRequest)
	if err != nil {
		return Response{}, err
	}
	defer httpResponse.Body.Close()
	var response Response
	if err := json.NewDecoder(io.LimitReader(httpResponse.Body, MaxRequestBytes)).Decode(&response); err != nil {
		return Response{}, err
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

func FormatJoin(result JoinResult) string {
	return strings.Join([]string{
		"Joined " + result.Record.Alias,
		"Host: " + result.VirtualHost,
		"IP: " + result.VirtualIP,
	}, "\n")
}

func FormatList(items []hubnet.HubListItem) string {
	if len(items) == 0 {
		return ""
	}
	lines := make([]string, 0, len(items))
	for _, item := range items {
		line := item.Alias + "\t" + string(item.Status)
		if item.Error != "" {
			line += "\t" + item.Error
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func ParseCommand(args []string) (Request, error) {
	request := Request{Version: Version}
	if len(args) == 0 {
		return request, errors.New("command required")
	}
	request.Command = args[0]
	switch request.Command {
	case "join":
		if len(args) != 2 {
			return request, errors.New("usage: hub-net join <code-or-url>")
		}
		request.Code = args[1]
	case "local":
		if len(args) > 2 {
			return request, errors.New("usage: hub-net local [hub-address]")
		}
		request.Address = DefaultLocalHubAddress
		if len(args) == 2 {
			request.Address = args[1]
		}
	case "leave":
		if len(args) != 2 {
			return request, errors.New("usage: hub-net leave <hubname>")
		}
		request.Alias = args[1]
	case "open", "close":
		if len(args) != 3 {
			return request, fmt.Errorf("usage: hub-net %s <port> <hubname>", request.Command)
		}
		port, err := strconv.ParseUint(args[1], 10, 16)
		if err != nil || port == 0 {
			return request, errors.New("port must be an integer from 1 to 65535")
		}
		request.Port = uint16(port)
		request.Alias = args[2]
	case "vpn":
		if len(args) != 3 || (args[1] != "allow" && args[1] != "remove") {
			return request, errors.New("usage: hub-net vpn <allow|remove> <hubname>")
		}
		if args[1] == "allow" {
			request.Command = "vpnAllow"
		} else {
			request.Command = "vpnRemove"
		}
		request.Alias = args[2]
	case "pause", "resume":
		if len(args) != 2 {
			return request, fmt.Errorf("usage: hub-net %s <hubname>", request.Command)
		}
		request.Alias = args[1]
	case "list", "removeAll":
		if len(args) != 1 {
			return request, fmt.Errorf("usage: hub-net %s", request.Command)
		}
	default:
		return request, fmt.Errorf("unknown command %q", request.Command)
	}
	return request, nil
}
