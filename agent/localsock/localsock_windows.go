//go:build windows

package localsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Path is the named pipe for path: path itself when it is a pipe, otherwise
// one derived from its directory and base name.
func Path(path string) string {
	if IsPipe(path) {
		return path
	}
	return pipeName(path)
}

// Listen creates the pipe with a protected DACL that admits SYSTEM, elevated
// Administrators, the agent's own account and access.Group. The pipe is
// created exclusively (a squatter makes Listen fail) and rejects remote
// clients.
func Listen(path string, access Access) (net.Listener, error) {
	descriptor, err := SecurityDescriptor(access)
	if err != nil {
		return nil, err
	}
	listener, err := winio.ListenPipe(Path(path), &winio.PipeConfig{SecurityDescriptor: descriptor})
	if err != nil {
		return nil, fmt.Errorf("localsock: listen %s: %w", Path(path), err)
	}
	return listener, nil
}

// SecurityDescriptor is the pipe's SDDL: owner SYSTEM, a protected DACL with
// full access for SYSTEM, Administrators (an ACE that counts only in an
// elevated token) and the current account, and read-write for the group.
func SecurityDescriptor(access Access) (string, error) {
	self, err := currentUserSID()
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	builder.WriteString("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if self != "S-1-5-18" {
		fmt.Fprintf(&builder, "(A;;GA;;;%s)", self)
	}
	if access.Group != "" {
		sid, _, _, err := windows.LookupSID("", access.Group)
		if err != nil {
			return "", fmt.Errorf("localsock: socket group %q: %w", access.Group, err)
		}
		fmt.Fprintf(&builder, "(A;;GRGW;;;%s)", sid.String())
	}
	return builder.String(), nil
}

func currentUserSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("localsock: current user: %w", err)
	}
	return user.User.Sid.String(), nil
}

// Remove is a no-op: a pipe disappears with its last handle.
func Remove(string) error { return nil }

// Dial connects to the pipe for path, at the Identification level so the
// agent can read the client's token (PeerUID) but not act as it.
func Dial(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeAccessImpLevel(ctx, Path(path), windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
}

var procGetNamedPipeClientProcessId = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeClientProcessId")

// ErrPeerUnknown is returned when a connection's client can't be identified.
var ErrPeerUnknown = errors.New("localsock: pipe client unknown")

// PeerUID maps a pipe client to the ipc package's uid convention: 0 for
// LocalSystem or a token in the enabled Administrators group (root), the
// agent's os.Getuid() (-1 on Windows) for the agent's own account, and 1
// for anyone else (a group member the DACL let in).
func PeerUID(conn net.Conn) (int, error) {
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, ErrPeerUnknown
	}
	var pid uint32
	if r, _, err := procGetNamedPipeClientProcessId.Call(fd.Fd(), uintptr(unsafe.Pointer(&pid))); r == 0 {
		return 0, fmt.Errorf("%w: %v", ErrPeerUnknown, err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, fmt.Errorf("%w: open process %d: %v", ErrPeerUnknown, pid, err)
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return 0, fmt.Errorf("%w: process token: %v", ErrPeerUnknown, err)
	}
	defer token.Close()
	return uidOf(token)
}

func uidOf(token windows.Token) (int, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return 0, fmt.Errorf("%w: token user: %v", ErrPeerUnknown, err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return 0, err
	}
	if user.User.Sid.Equals(system) {
		return 0, nil
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, err
	}
	if member, err := tokenHasEnabledGroup(token, administrators); err == nil && member {
		return 0, nil
	}
	self, err := currentUserSID()
	if err != nil {
		return 0, err
	}
	if user.User.Sid.String() == self {
		return -1, nil
	}
	return 1, nil
}

// tokenHasEnabledGroup reports whether a primary token (not an impersonation
// token, which IsMember needs) has group enabled: a filtered admin token
// lists Administrators as deny-only, which doesn't count.
func tokenHasEnabledGroup(token windows.Token, group *windows.SID) (bool, error) {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false, err
	}
	for _, entry := range groups.AllGroups() {
		if entry.Sid.Equals(group) && entry.Attributes&windows.SE_GROUP_ENABLED != 0 && entry.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return true, nil
		}
	}
	return false, nil
}
