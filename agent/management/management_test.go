package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hubnet "github.com/v57/hub-net"
	"github.com/v57/hub-net/membership"
	"github.com/v57/hub-net/publications"
	"github.com/v57/hub-net/supervisor"
)

type fakeDaemon struct {
	mu           sync.Mutex
	items        map[string]hubnet.HubListItem
	shares       map[string]publications.Entry
	failProtocol string
	gateways     map[string]bool
}

func (d *fakeDaemon) SetGateway(_ context.Context, id string, allowed bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.gateways[id] = allowed
	return nil
}

func (d *fakeDaemon) OpenShare(_ context.Context, _ string, entry publications.Entry) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if entry.Protocol == d.failProtocol {
		return errors.New("publish failed")
	}
	d.shares[entry.Name] = entry
	return nil
}

func (d *fakeDaemon) CloseShare(_ context.Context, _, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.shares, name)
	return nil
}

func (d *fakeDaemon) Add(value supervisor.Membership) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.items[value.ID] = hubnet.HubListItem{ID: value.ID, Alias: value.Alias, Status: supervisor.StatusConnected}
	return nil
}

func (d *fakeDaemon) Remove(id string) error {
	d.mu.Lock()
	delete(d.items, id)
	d.mu.Unlock()
	return nil
}

func (d *fakeDaemon) List() []hubnet.HubListItem {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]hubnet.HubListItem, 0, len(d.items))
	for _, item := range d.items {
		result = append(result, item)
	}
	return result
}

func testService(t *testing.T, join JoinFunc) (*Service, *fakeDaemon, *membership.Store) {
	t.Helper()
	store, err := membership.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	daemon := &fakeDaemon{
		items:    make(map[string]hubnet.HubListItem),
		shares:   make(map[string]publications.Entry),
		gateways: make(map[string]bool),
	}
	service, err := NewService(daemon, store, join, nil)
	if err != nil {
		t.Fatal(err)
	}
	return service, daemon, store
}

func result(id, alias string) JoinResult {
	address, _ := json.Marshal("ws://hub")
	return JoinResult{
		Record: membership.Record{
			ID: id, Alias: alias, Header: alias, HubAddress: address,
			InterfaceName: "hub00000001",
		},
		VirtualHost: "service." + alias + ".hub.invalid",
		VirtualIP:   "10.0.0.2",
	}
}

func TestJoinExactOutputAndSocketPermissions(t *testing.T) {
	service, _, _ := testService(t, func(context.Context, string) (JoinResult, error) {
		return result("one", "work"), nil
	})
	socketDir, err := os.MkdirTemp("/tmp", "hub-net-management-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "command.sock")
	server, err := NewServer(socket, service)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)

	info, err := filepath.Glob(socket)
	if err != nil || len(info) != 1 {
		t.Fatalf("socket missing: %v", err)
	}
	mode, err := statMode(socket)
	if err != nil {
		t.Fatal(err)
	}
	if mode != 0o600 {
		t.Fatalf("socket mode = %o", mode)
	}
	response, err := NewClient(socket).Execute(context.Background(), Request{
		Version: Version, Command: "join", Code: "code",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := FormatJoin(*response.Joined)
	want := "Joined work\nHost: service.work.hub.invalid\nIP: 10.0.0.2"
	if got != want {
		t.Fatalf("output = %q", got)
	}
}

func statMode(path string) (uint32, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return uint32(info.Mode().Perm()), nil
}

func TestCommandsSerializeAndLeaveIsIdempotent(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	var sequence atomic.Int32
	service, daemon, store := testService(t, func(context.Context, string) (JoinResult, error) {
		now := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if now <= old || maximum.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		n := sequence.Add(1)
		return result(string(rune('a'+n)), string(rune('a'+n))), nil
	})
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response := service.Execute(context.Background(), Request{Version: Version, Command: "join", Code: "code"})
			if response.Error != "" {
				t.Errorf("join: %s", response.Error)
			}
		}()
	}
	wait.Wait()
	if maximum.Load() != 1 {
		t.Fatalf("maximum concurrent mutations = %d", maximum.Load())
	}

	stored := result("leave-id", "leave")
	if err := store.Stage(stored.Record); err != nil {
		t.Fatal(err)
	}
	committed, err := store.Commit(stored.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.Add(toSupervisor(committed)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		response := service.Execute(context.Background(), Request{Version: Version, Command: "leave", Alias: "leave"})
		if response.Error != "" {
			t.Fatal(response.Error)
		}
	}
}

func TestRemoveAllDeletesEveryLiveAndPersistedMembership(t *testing.T) {
	service, daemon, store := testService(t, nil)
	for index, alias := range []string{"home", "work"} {
		joined := result(alias+"-id", alias)
		joined.Record.InterfaceName = "hub0000000" + string(rune('1'+index))
		if err := store.Stage(joined.Record); err != nil {
			t.Fatal(err)
		}
		stored, err := store.Commit(joined.Record.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := daemon.Add(toSupervisor(stored)); err != nil {
			t.Fatal(err)
		}
	}

	for range 2 {
		response := service.Execute(context.Background(), Request{
			Version: Version, Command: "removeAll",
		})
		if response.Error != "" {
			t.Fatal(response.Error)
		}
	}
	if items := daemon.List(); len(items) != 0 {
		t.Fatalf("live memberships after removeAll = %+v", items)
	}
	records, diagnostics, err := store.Load()
	if err != nil || len(records) != 0 || len(diagnostics) != 0 {
		t.Fatalf("persisted memberships after removeAll = %+v, diagnostics=%+v, err=%v",
			records, diagnostics, err)
	}
}

func TestServerRejectsOversizedRequest(t *testing.T) {
	service, _, _ := testService(t, nil)
	socketDir, err := os.MkdirTemp("/tmp", "hub-net-management-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "command.sock")
	server, err := NewServer(socket, service)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)
	client := NewClient(socket)
	request, err := http.NewRequest(http.MethodPost, "http://unix/v1/command",
		bytes.NewReader(bytes.Repeat([]byte("x"), MaxRequestBytes+1)))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestOpenClosePersistBothProtocolsAndAreIdempotent(t *testing.T) {
	service, daemon, store := testService(t, nil)
	joined := result("ports-id", "work")
	if err := store.Stage(joined.Record); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Commit(joined.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.Add(toSupervisor(stored)); err != nil {
		t.Fatal(err)
	}
	open := Request{Version: Version, Command: "open", Port: 8080, Alias: "work"}
	for range 2 {
		if response := service.Execute(context.Background(), open); response.Error != "" {
			t.Fatal(response.Error)
		}
	}
	entries, err := publications.Load(filepath.Join(stored.StateDir, "publications.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || len(daemon.shares) != 2 {
		t.Fatalf("persisted = %v, live = %v", entries, daemon.shares)
	}
	for _, protocol := range []string{"tcp", "udp"} {
		name := "port-8080-" + protocol
		if entry, found := daemon.shares[name]; !found || entry.Protocol != protocol {
			t.Fatalf("missing deterministic %s share: %v", protocol, daemon.shares)
		}
	}
	closeRequest := Request{Version: Version, Command: "close", Port: 8080, Alias: "work"}
	for range 2 {
		if response := service.Execute(context.Background(), closeRequest); response.Error != "" {
			t.Fatal(response.Error)
		}
	}
	entries, err = publications.Load(filepath.Join(stored.StateDir, "publications.json"))
	if err != nil || len(entries) != 0 || len(daemon.shares) != 0 {
		t.Fatalf("close persisted = %v, live = %v, err = %v", entries, daemon.shares, err)
	}
}

func TestOpenRollsBackTCPAndPersistenceWhenUDPFails(t *testing.T) {
	service, daemon, store := testService(t, nil)
	joined := result("rollback-id", "work")
	if err := store.Stage(joined.Record); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Commit(joined.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.Add(toSupervisor(stored)); err != nil {
		t.Fatal(err)
	}
	daemon.failProtocol = "udp"
	response := service.Execute(context.Background(), Request{
		Version: Version, Command: "open", Port: 9000, Alias: "work",
	})
	if response.Error == "" {
		t.Fatal("UDP failure accepted")
	}
	entries, err := publications.Load(filepath.Join(stored.StateDir, "publications.json"))
	if err != nil || len(entries) != 0 || len(daemon.shares) != 0 {
		t.Fatalf("rollback persisted = %v, live = %v, err = %v", entries, daemon.shares, err)
	}
}

func TestParseOpenClosePortValidation(t *testing.T) {
	for _, command := range []string{"open", "close"} {
		request, err := ParseCommand([]string{command, "65535", "work"})
		if err != nil || request.Port != 65535 || request.Alias != "work" {
			t.Fatalf("%s parse = %+v, %v", command, request, err)
		}
		for _, invalid := range []string{"0", "65536", "x", "-1"} {
			if _, err := ParseCommand([]string{command, invalid, "work"}); err == nil {
				t.Fatalf("%s accepted port %q", command, invalid)
			}
		}
	}
}

func TestVPNAllowRemovePersistsAndIsIdempotent(t *testing.T) {
	service, daemon, store := testService(t, nil)
	joined := result("gateway-id", "work")
	if err := store.Stage(joined.Record); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Commit(joined.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.Add(toSupervisor(stored)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		args    []string
		allowed bool
	}{
		{[]string{"vpn", "allow", "work"}, true},
		{[]string{"vpn", "allow", "work"}, true},
		{[]string{"vpn", "remove", "work"}, false},
		{[]string{"vpn", "remove", "work"}, false},
	} {
		request, err := ParseCommand(test.args)
		if err != nil {
			t.Fatal(err)
		}
		if response := service.Execute(context.Background(), request); response.Error != "" {
			t.Fatal(response.Error)
		}
		reloaded, found, err := store.FindAlias("work")
		if err != nil || !found || reloaded.Record.GatewayAllowed != test.allowed {
			t.Fatalf("persisted allowed = %v, found = %v, err = %v", reloaded.Record.GatewayAllowed, found, err)
		}
		if daemon.gateways["gateway-id"] != test.allowed {
			t.Fatalf("live allowed = %v", daemon.gateways["gateway-id"])
		}
	}
}

func TestPauseResumeKeepsTheMembershipAndListsIt(t *testing.T) {
	service, daemon, store := testService(t, nil)
	joined := result("pause-id", "work")
	joined.Record.CanonicalIPv4 = "100.96.0.3"
	if err := store.Stage(joined.Record); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Commit(joined.Record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.Add(toSupervisor(stored)); err != nil {
		t.Fatal(err)
	}
	execute := func(args ...string) Response {
		t.Helper()
		request, err := ParseCommand(args)
		if err != nil {
			t.Fatal(err)
		}
		response := service.Execute(context.Background(), request)
		if response.Error != "" {
			t.Fatal(response.Error)
		}
		return response
	}
	for range 2 {
		execute("pause", "work")
		if len(daemon.List()) != 0 {
			t.Fatal("a paused membership keeps its session")
		}
		items := execute("list").Items
		if len(items) != 1 || items[0].Status != supervisor.StatusPaused || items[0].OverlayIPv4 != "100.96.0.3" ||
			items[0].HubAddress != "ws://hub" {
			t.Fatalf("list while paused = %+v", items)
		}
	}
	for range 2 {
		execute("resume", "work")
		items := execute("list").Items
		if len(items) != 1 || items[0].Status != supervisor.StatusConnected {
			t.Fatalf("list after resume = %+v", items)
		}
	}
	reloaded, found, err := store.FindAlias("work")
	if err != nil || !found || reloaded.Record.Paused {
		t.Fatalf("persisted paused = %v, found = %v, err = %v", reloaded.Record.Paused, found, err)
	}
	execute("pause", "work")
	execute("leave", "work")
	if items := execute("list").Items; len(items) != 0 {
		t.Fatalf("leaving a paused membership leaves %+v", items)
	}
}
