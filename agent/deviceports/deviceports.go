// Package deviceports is this device's own say over which of its ports another
// device may open over Hub Network. A hub-signed grant names ports; the device
// opens only those also on this list, so a Hub can narrow what's reachable but
// never widen it.
//
// The list is made of what this device itself put there:
//   - the shares it publishes (`hub-net open`), which the agent passes in;
//   - the ports local services had attested here, kept 31 days from the last
//     attestation so a restart doesn't close them;
//   - ports the user allowed (`hub-net ports allow tcp/8080`);
//   - the SSH port, only after `hub-net ports ssh on`. An attestation doesn't
//     count for it: another process of this user can't turn SSH on.
package deviceports

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	version = 1
	// DefaultSSHPort is the port `ssh on` opens unless it names another.
	DefaultSSHPort = 22
	// AttestedLifetime is how long an attested port stays without a new
	// attestation; a grant lives at most as long, and services attest again
	// each time they connect.
	AttestedLifetime = 31 * 24 * time.Hour
	// maximumAttested bounds what a local process can add to the file.
	maximumAttested = 256
)

// ErrInvalidPort is a port that isn't `tcp/N` or `udp/N`.
var ErrInvalidPort = errors.New("deviceports: use tcp/<port> or udp/<port>")

// Port is one protocol and port of this device.
type Port struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

func (p Port) String() string { return p.Protocol + "/" + strconv.Itoa(int(p.Port)) }

// Parse reads `tcp/8080`.
func Parse(value string) (Port, error) {
	protocol, number, ok := strings.Cut(value, "/")
	if !ok || (protocol != "tcp" && protocol != "udp") {
		return Port{}, ErrInvalidPort
	}
	parsed, err := strconv.ParseUint(number, 10, 16)
	if err != nil || parsed == 0 {
		return Port{}, ErrInvalidPort
	}
	return Port{Protocol: protocol, Port: uint16(parsed)}, nil
}

type attestedPort struct {
	Port
	At time.Time `json:"at"`
}

type state struct {
	Version  int            `json:"version"`
	SSH      bool           `json:"ssh"`
	SSHPort  uint16         `json:"sshPort,omitempty"`
	Allowed  []Port         `json:"allowed,omitempty"`
	Attested []attestedPort `json:"attested,omitempty"`
}

// List is the file `device-ports.json`, one per device across its Hubs. A
// missing file is an empty list with SSH off.
type List struct {
	mu       sync.Mutex
	path     string
	now      func() time.Time
	state    state
	modified time.Time
}

// Open reads the list. A file it can't read is an error: the caller opens
// nothing rather than guessing.
func Open(path string) (*List, error) {
	list := &List{path: path, now: time.Now, state: state{Version: version}}
	if err := list.load(); err != nil {
		return nil, err
	}
	return list, nil
}

// SetNowForTest sets the clock.
func (l *List) SetNowForTest(now func() time.Time) { l.now = now }

func (l *List) load() error {
	info, err := os.Stat(l.path)
	if errors.Is(err, os.ErrNotExist) {
		l.state = state{Version: version}
		l.modified = time.Time{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("deviceports: read: %w", err)
	}
	raw, err := os.ReadFile(l.path)
	if err != nil {
		return fmt.Errorf("deviceports: read: %w", err)
	}
	var value state
	if err := json.Unmarshal(raw, &value); err != nil || value.Version != version {
		return errors.New("deviceports: invalid list")
	}
	l.state = value
	l.modified = info.ModTime()
	return nil
}

// Reload picks up `hub-net ports`, which edits the file from another process,
// and reports whether anything changed.
func (l *List) Reload() (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	info, err := os.Stat(l.path)
	var modified time.Time
	if err == nil {
		modified = info.ModTime()
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("deviceports: read: %w", err)
	}
	if modified.Equal(l.modified) {
		return false, nil
	}
	return true, l.load()
}

func (l *List) sshPort() Port {
	port := l.state.SSHPort
	if port == 0 {
		port = DefaultSSHPort
	}
	return Port{Protocol: "tcp", Port: port}
}

// Allows says whether this device lets a port open. `shares` are the shares
// the device publishes itself; a share the user opened on the SSH port counts,
// being as explicit as turning SSH on.
func (l *List) Allows(port Port, shares []Port) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.allowsLocked(port, shares)
}

func (l *List) allowsLocked(port Port, shares []Port) bool {
	for _, share := range shares {
		if share == port {
			return true
		}
	}
	for _, allowed := range l.state.Allowed {
		if allowed == port {
			return true
		}
	}
	if port == l.sshPort() {
		return l.state.SSH
	}
	now := l.now()
	for _, attested := range l.state.Attested {
		if attested.Port == port && now.Sub(attested.At) < AttestedLifetime {
			return true
		}
	}
	return false
}

// Filter keeps the ports this device lets open.
func (l *List) Filter(ports []Port, shares []Port) []Port {
	l.mu.Lock()
	defer l.mu.Unlock()
	var kept []Port
	for _, port := range ports {
		if l.allowsLocked(port, shares) {
			kept = append(kept, port)
		}
	}
	return kept
}

// NoteAttested records that a local service had this port attested here.
func (l *List) NoteAttested(port Port) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	kept := l.state.Attested[:0]
	for _, attested := range l.state.Attested {
		if attested.Port != port && now.Sub(attested.At) < AttestedLifetime {
			kept = append(kept, attested)
		}
	}
	if len(kept) >= maximumAttested {
		sort.Slice(kept, func(i, j int) bool { return kept[i].At.After(kept[j].At) })
		kept = kept[:maximumAttested-1]
	}
	l.state.Attested = append(kept, attestedPort{Port: port, At: now})
	return l.saveLocked()
}

// Allow adds a port to the user's list.
func (l *List) Allow(port Port) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, allowed := range l.state.Allowed {
		if allowed == port {
			return nil
		}
	}
	l.state.Allowed = append(l.state.Allowed, port)
	return l.saveLocked()
}

// Remove takes a port off the user's list.
func (l *List) Remove(port Port) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.state.Allowed[:0]
	for _, allowed := range l.state.Allowed {
		if allowed != port {
			kept = append(kept, allowed)
		}
	}
	l.state.Allowed = kept
	return l.saveLocked()
}

// SetSSH turns SSH on or off; a port of 0 keeps the one set before.
func (l *List) SetSSH(enabled bool, port uint16) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.state.SSH = enabled
	if port != 0 {
		l.state.SSHPort = port
	}
	return l.saveLocked()
}

// Describe is what `hub-net ports list` prints.
func (l *List) Describe() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	lines := []string{"ssh " + map[bool]string{true: "on", false: "off"}[l.state.SSH] + " (" + l.sshPort().String() + ")"}
	for _, allowed := range l.state.Allowed {
		lines = append(lines, "allowed "+allowed.String())
	}
	now := l.now()
	for _, attested := range l.state.Attested {
		if now.Sub(attested.At) < AttestedLifetime {
			lines = append(lines, "attested "+attested.Port.String())
		}
	}
	return strings.Join(lines, "\n")
}

func (l *List) saveLocked() error {
	l.state.Version = version
	raw, err := json.Marshal(l.state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return fmt.Errorf("deviceports: create directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(l.path), ".device-ports-")
	if err != nil {
		return fmt.Errorf("deviceports: create temp: %w", err)
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0o600); err == nil {
		_, err = temp.Write(raw)
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temp.Name(), l.path)
	}
	if err != nil {
		return fmt.Errorf("deviceports: save: %w", err)
	}
	if info, err := os.Stat(l.path); err == nil {
		l.modified = info.ModTime()
	}
	return nil
}

// Command runs `hub-net ports …` on the file at path and returns what to print.
func Command(path string, args []string) (string, error) {
	const usage = "usage: hub-net ports [list | allow <tcp/port> | remove <tcp/port> | ssh on [port] | ssh off]"
	list, err := Open(path)
	if err != nil {
		return "", err
	}
	if len(args) == 0 || args[0] == "list" {
		return list.Describe(), nil
	}
	switch args[0] {
	case "allow", "remove":
		if len(args) != 2 {
			return "", errors.New(usage)
		}
		port, err := Parse(args[1])
		if err != nil {
			return "", err
		}
		if args[0] == "allow" {
			return "", list.Allow(port)
		}
		return "", list.Remove(port)
	case "ssh":
		if len(args) >= 2 && args[1] == "off" && len(args) == 2 {
			return "", list.SetSSH(false, 0)
		}
		if len(args) >= 2 && args[1] == "on" && len(args) <= 3 {
			var port uint16
			if len(args) == 3 {
				parsed, err := strconv.ParseUint(args[2], 10, 16)
				if err != nil || parsed == 0 {
					return "", errors.New(usage)
				}
				port = uint16(parsed)
			}
			return "", list.SetSSH(true, port)
		}
	}
	return "", errors.New(usage)
}
