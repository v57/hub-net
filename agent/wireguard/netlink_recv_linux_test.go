//go:build linux

package wireguard

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// A request's reply skips what earlier requests left on the socket and
// includes everything up to its ACK, also when the ACK comes in a datagram of
// its own (genetlink's NEWFAMILY, then the ACK).
func TestRecvReplyReadsItsOwnRequestToTheAck(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	message := func(msgType uint16, seq uint32, payload ...byte) []byte {
		out := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(payload))
		binary.LittleEndian.PutUint32(out[0:], uint32(unix.NLMSG_HDRLEN+len(payload)))
		binary.LittleEndian.PutUint16(out[4:], msgType)
		binary.LittleEndian.PutUint32(out[8:], seq)
		return append(out, payload...)
	}
	ack := func(seq uint32) []byte { return message(unix.NLMSG_ERROR, seq, 0, 0, 0, 0) }
	for _, datagram := range [][]byte{
		ack(1),                       // left by an earlier request
		message(0x20, 2, 1, 2, 3, 4), // the reply to request 2
		ack(2),                       // and its ACK, in a datagram of its own
		message(0x20, 3, 9, 9, 9, 9), // the next request's
	} {
		if _, err := unix.Write(fds[1], datagram); err != nil {
			t.Fatal(err)
		}
	}
	reply, err := recvReply(fds[0], 2)
	if err != nil {
		t.Fatal(err)
	}
	messages := splitMessages(reply)
	if len(messages) != 2 || binary.LittleEndian.Uint16(messages[0][4:]) != 0x20 || messages[0][unix.NLMSG_HDRLEN] != 1 ||
		binary.LittleEndian.Uint16(messages[1][4:]) != unix.NLMSG_ERROR {
		t.Fatalf("reply = %x", reply)
	}
	if err := ackOrError(reply); err != nil {
		t.Fatal(err)
	}
	// The next request's reply is still there
	next, err := recvNetlink(fds[0])
	if err != nil || binary.LittleEndian.Uint32(next[8:]) != 3 {
		t.Fatalf("next = %x, %v", next, err)
	}
}
