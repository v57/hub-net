package nodeclient

import (
	"net"
	"testing"
	"time"

	"github.com/v57/hub-net-node/protocol"
)

// A deadline left on the long-lived registration connection by an earlier
// write must not fail later writes (the second join through one inviter used
// to fail with "i/o timeout").
func TestWriteEnvelopeIgnoresStaleDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetWriteDeadline(time.Now().Add(-time.Second))

	read := make(chan error, 1)
	go func() {
		_, err := readClientFrame(server)
		read <- err
	}()
	envelope := protocol.Envelope{MajorVersion: protocol.MajorVersion, Type: protocol.MessageCloseSession, SessionID: "s"}
	if err := WriteEnvelope(client, envelope); err != nil {
		t.Fatalf("WriteEnvelope with a stale deadline: %v", err)
	}
	if err := <-read; err != nil {
		t.Fatalf("read: %v", err)
	}
}

// readClientFrame drains one masked client frame.
func readClientFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := conn.Read(header); err != nil {
		return nil, err
	}
	length := int(header[1] & 0x7f)
	if length == 126 {
		extended := make([]byte, 2)
		if _, err := conn.Read(extended); err != nil {
			return nil, err
		}
		length = int(extended[0])<<8 | int(extended[1])
	}
	rest := make([]byte, 4+length)
	total := 0
	for total < len(rest) {
		n, err := conn.Read(rest[total:])
		if err != nil {
			return nil, err
		}
		total += n
	}
	return rest[4:], nil
}
