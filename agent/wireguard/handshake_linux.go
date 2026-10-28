//go:build linux

package wireguard

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// LastHandshakes reads each peer's latest handshake from the kernel
// (WG_CMD_GET_DEVICE). The adapter's cached configuration does not know it.
func (a *linuxAdapter) LastHandshakes() (map[string]time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.up {
		return nil, errors.New("wireguard: interface is down")
	}
	hdrLen := unix.NLMSG_HDRLEN + genlmsghdrLen
	w := newNlmsgWriter(make([]byte, hdrLen))
	binary.LittleEndian.PutUint16(w.buf[4:], a.familyID)
	binary.LittleEndian.PutUint16(w.buf[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	w.buf[unix.NLMSG_HDRLEN] = byte(unix.WG_CMD_GET_DEVICE)
	w.buf[unix.NLMSG_HDRLEN+1] = WireGuardGenlVersion
	w.PutString(unix.WGDEVICE_A_IFNAME, a.config.Name)
	if err := a.send(w.Bytes()); err != nil {
		return nil, fmt.Errorf("wireguard: get device: %w", err)
	}
	out := make(map[string]time.Time)
	for {
		chunk, err := recvNetlink(a.fd)
		if err != nil {
			return nil, fmt.Errorf("wireguard: get device: %w", err)
		}
		for _, msg := range splitMessages(chunk) {
			msgType, _, body, err := parseNlmsghdr(msg)
			if err != nil {
				return nil, err
			}
			switch msgType {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				if err := ackOrError(msg); err != nil {
					return nil, fmt.Errorf("wireguard: get device: %w", err)
				}
				return out, nil
			}
			if len(body) < genlmsghdrLen {
				continue
			}
			parseDeviceHandshakes(body[genlmsghdrLen:], out)
		}
	}
}

// parseDeviceHandshakes walks the WGDEVICE_A_* attributes of one GET_DEVICE
// reply and records each peer's WGPEER_A_LAST_HANDSHAKE_TIME.
func parseDeviceHandshakes(attributes []byte, out map[string]time.Time) {
	const nested = 0x8000
	device := newNlmsgReader(attributes, 0)
	for {
		attrType, payload, ok := device.Next()
		if !ok {
			return
		}
		if attrType&^nested != unix.WGDEVICE_A_PEERS {
			continue
		}
		peers := newNlmsgReader(payload, 0)
		for {
			_, peer, ok := peers.Next()
			if !ok {
				break
			}
			var key []byte
			var at time.Time
			fields := newNlmsgReader(peer, 0)
			for {
				fieldType, value, ok := fields.Next()
				if !ok {
					break
				}
				switch fieldType &^ nested {
				case unix.WGPEER_A_PUBLIC_KEY:
					key = value
				case unix.WGPEER_A_LAST_HANDSHAKE_TIME:
					// struct __kernel_timespec: int64 seconds, int64 nanoseconds
					if len(value) >= 16 {
						seconds := int64(binary.NativeEndian.Uint64(value[0:8]))
						nanoseconds := int64(binary.NativeEndian.Uint64(value[8:16]))
						if seconds != 0 || nanoseconds != 0 {
							at = time.Unix(seconds, nanoseconds)
						}
					}
				}
			}
			if len(key) == 32 && !at.IsZero() {
				out[base64.StdEncoding.EncodeToString(key)] = at
			}
		}
	}
}
