package localsock

import (
	"bufio"
	"context"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPipeNameIsPerDirectory(t *testing.T) {
	a := pipeName(`C:\ProgramData\hub-net\memberships\a\service.sock`)
	b := pipeName(`C:\ProgramData\hub-net\memberships\b\service.sock`)
	if a == b {
		t.Fatal("two directories share a pipe")
	}
	if !strings.HasPrefix(a, `\\.\pipe\hub-net-service-`) || !IsPipe(a) {
		t.Fatalf("pipe name %q", a)
	}
	if pipeName(`C:\ProgramData\HUB-NET\memberships\a\service.sock`) != a {
		t.Fatal("pipe name depends on the directory's case")
	}
	if pipeName("/var/lib/hub-net/command.sock") == pipeName("/var/lib/hub-net/service.sock") {
		t.Fatal("two sockets in one directory share a pipe")
	}
}

// echo serves one line back on every connection.
func echo(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err == nil {
				conn.Write([]byte(line))
			}
		}()
	}
}

func socketPath(t *testing.T) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(t.TempDir(), "test.sock")
	}
	// Unix socket paths are short: macOS allows 104 bytes.
	dir, err := filepathTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeAll(dir) })
	return filepath.Join(dir, "test.sock")
}

func TestListenDialRoundTrip(t *testing.T) {
	path := socketPath(t)
	listener, err := Listen(path, Access{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go echo(listener)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, path)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Write([]byte("ping\n"))
	line, err := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if err != nil || line != "ping\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
	listener.Close()
	if err := Remove(path); err != nil {
		t.Fatal(err)
	}
	if conn, err := Dial(ctx, path); err == nil {
		conn.Close()
		t.Fatal("Dial reached a closed endpoint")
	}
}
