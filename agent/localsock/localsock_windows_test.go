//go:build windows

package localsock

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func filepathTemp() (string, error) { return os.MkdirTemp("", "ls") }
func removeAll(dir string)          { os.RemoveAll(dir) }

func TestSecurityDescriptorIsProtectedAndScoped(t *testing.T) {
	sddl, err := SecurityDescriptor(Access{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sddl, "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)") {
		t.Fatalf("SDDL %q", sddl)
	}
	for _, open := range []string{";;;WD)", ";;;AU)", ";;;BU)", ";;;AN)", ";;;NU)"} {
		if strings.Contains(sddl, open) {
			t.Fatalf("SDDL %q admits %s", sddl, open)
		}
	}
	withGroup, err := SecurityDescriptor(Access{Group: "Users"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(withGroup, "(A;;GRGW;;;S-1-5-32-545)") {
		t.Fatalf("group SDDL %q", withGroup)
	}
	if _, err := SecurityDescriptor(Access{Group: "no-such-group-hub-net"}); err == nil {
		t.Fatal("unknown group accepted")
	}
}

// TestPipeDACLOnObject reads the DACL back from a live pipe, through a
// client handle (opening the pipe by name takes an instance like a client).
func TestPipeDACLOnObject(t *testing.T) {
	path := `\\.\pipe\hub-net-test-dacl-` + time.Now().Format("150405.000000")
	listener, err := Listen(path, Access{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		if conn, err := listener.Accept(); err == nil {
			defer conn.Close()
			time.Sleep(5 * time.Second)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	descriptor, err := windows.GetSecurityInfo(windows.Handle(client.(interface{ Fd() uintptr }).Fd()), windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL not protected: %s", descriptor)
	}
	text := descriptor.String()
	if strings.Contains(text, ";;;WD)") || strings.Contains(text, ";;;AU)") || strings.Contains(text, ";;;BU)") {
		t.Fatalf("pipe DACL too open: %s", text)
	}
	if !strings.Contains(text, ";;;SY)") || !strings.Contains(text, ";;;BA)") {
		t.Fatalf("pipe DACL misses SYSTEM or Administrators: %s", text)
	}
	t.Logf("pipe security: %s", text)
}

// A second listener on the same pipe (a squatter, or a second agent) fails:
// the first instance is created exclusively.
func TestListenRefusesExistingPipe(t *testing.T) {
	path := `\\.\pipe\hub-net-test-squat-` + time.Now().Format("150405.000000")
	squatter, err := winio.ListenPipe(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	if listener, err := Listen(path, Access{}); err == nil {
		listener.Close()
		t.Fatal("Listen took over a pipe another listener created")
	}
}

func TestPeerUIDOfSelf(t *testing.T) {
	path := `\\.\pipe\hub-net-test-peer-` + time.Now().Format("150405.000000")
	listener, err := Listen(path, Access{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()
	uid, err := PeerUID(server)
	if err != nil {
		t.Fatal(err)
	}
	want := os.Getuid()
	if windows.GetCurrentProcessToken().IsElevated() {
		want = 0
	}
	if user, _ := windows.GetCurrentProcessToken().GetTokenUser(); user != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		want = 0
	}
	if uid != want {
		t.Fatalf("PeerUID = %d, want %d", uid, want)
	}
	if _, err := PeerUID(&net.TCPConn{}); !errors.Is(err, ErrPeerUnknown) {
		t.Fatalf("PeerUID of a non-pipe: %v", err)
	}
}

// TestRemoteClientRejected dials the pipe the way a remote client would,
// through the machine's own name: FILE_PIPE_REJECT_REMOTE_CLIENTS refuses it.
func TestRemoteClientRejected(t *testing.T) {
	name := "hub-net-test-remote-" + time.Now().Format("150405.000000")
	listener, err := Listen(`\\.\pipe\`+name, Access{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	host, err := os.Hostname()
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, `\\`+host+`\pipe\`+name)
	if err == nil {
		conn.Close()
		t.Fatal("pipe accepted a client through the network redirector")
	}
}
