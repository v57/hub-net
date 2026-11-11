//go:build windows

package wireguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
)

// SendFromPort sends one UDP datagram to destination with source port port,
// the port WireGuardNT listens on, through a raw socket (Administrators). The
// stack fills in the IPv4 header with a local source address, which Windows
// allows on raw UDP sockets; a zero UDP checksum means none. IPv6 raw UDP
// needs the checksum over the source address the stack picks, so an IPv6
// node isn't probed: the link falls back as it does without a probe.
func SendFromPort(port uint16, destination netip.AddrPort, payload []byte) error {
	address := destination.Addr().Unmap()
	if !address.IsValid() || destination.Port() == 0 {
		return fmt.Errorf("wireguard: probe destination %s", destination)
	}
	if !address.Is4() {
		return fmt.Errorf("wireguard: IPv6 probe: %w", ErrPlatformUnsupported)
	}
	datagram := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(datagram[0:2], port)
	binary.BigEndian.PutUint16(datagram[2:4], destination.Port())
	binary.BigEndian.PutUint16(datagram[4:6], uint16(len(datagram)))
	copy(datagram[8:], payload)
	socket, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_UDP)
	if err != nil {
		if errors.Is(err, windows.WSAEACCES) {
			return fmt.Errorf("wireguard: probe needs Administrators: %w", err)
		}
		return fmt.Errorf("wireguard: probe socket: %w", err)
	}
	defer windows.Closesocket(socket)
	if err := windows.Sendto(socket, datagram, 0, &windows.SockaddrInet4{Addr: address.As4()}); err != nil {
		return fmt.Errorf("wireguard: send probe: %w", err)
	}
	return nil
}
