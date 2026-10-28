//go:build linux

package wireguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// SendFromPort sends one UDP datagram to destination with source port port,
// the port kernel WireGuard listens on. A peer link's coordinator must see
// the NAT mapping of WireGuard's own socket, which no other socket can bind,
// so the datagram goes out through a raw socket (CAP_NET_RAW). Any answer
// reaches WireGuard's socket, which drops it.
func SendFromPort(port uint16, destination netip.AddrPort, payload []byte) error {
	address := destination.Addr().Unmap()
	if !address.IsValid() || destination.Port() == 0 {
		return fmt.Errorf("wireguard: probe destination %s", destination)
	}
	datagram := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(datagram[0:2], port)
	binary.BigEndian.PutUint16(datagram[2:4], destination.Port())
	binary.BigEndian.PutUint16(datagram[4:6], uint16(len(datagram)))
	copy(datagram[8:], payload)
	if address.Is4() {
		// The kernel adds the IP header; a zero UDP checksum means none (IPv4).
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
		if err != nil {
			return fmt.Errorf("wireguard: probe socket: %w", err)
		}
		defer unix.Close(fd)
		return sendRaw(fd, datagram, &unix.SockaddrInet4{Addr: address.As4()})
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("wireguard: probe socket: %w", err)
	}
	defer unix.Close(fd)
	// IPv6 requires the checksum: the kernel fills it in at offset 6.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_CHECKSUM, 6); err != nil {
		return fmt.Errorf("wireguard: probe checksum: %w", err)
	}
	return sendRaw(fd, datagram, &unix.SockaddrInet6{Addr: address.As16()})
}

func sendRaw(fd int, datagram []byte, to unix.Sockaddr) error {
	if err := unix.Sendto(fd, datagram, 0, to); err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("wireguard: probe needs CAP_NET_RAW: %w", err)
		}
		return fmt.Errorf("wireguard: send probe: %w", err)
	}
	return nil
}
