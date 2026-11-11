//go:build windows

package enforcement

// iphlpapi.dll calls: the interface LUID WFP conditions name, and the IPv4
// TCP table that TerminateResource resets connections in.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procConvertInterfaceAliasToLuid = modIphlpapi.NewProc("ConvertInterfaceAliasToLuid")
	procGetTcpTable                 = modIphlpapi.NewProc("GetTcpTable")
	procSetTcpEntry                 = modIphlpapi.NewProc("SetTcpEntry")
	iphlpProcs                      = []*windows.LazyProc{procConvertInterfaceAliasToLuid, procGetTcpTable, procSetTcpEntry}

	errInterfaceNotFound = errors.New("enforcement: overlay interface not found")
)

const (
	mibTCPStateListen    = 2  // MIB_TCP_STATE_LISTEN
	mibTCPStateDeleteTCB = 12 // MIB_TCP_STATE_DELETE_TCB
)

// interfaceLUID returns the NET_LUID of the adapter whose alias is name
// (WireGuardNT names its adapter's alias after the tunnel).
func interfaceLUID(name string) (uint64, error) {
	alias, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	if err := procConvertInterfaceAliasToLuid.Find(); err != nil {
		return 0, err
	}
	var luid uint64
	r1, _, _ := procConvertInterfaceAliasToLuid.Call(uintptr(unsafe.Pointer(alias)), uintptr(unsafe.Pointer(&luid)))
	if r1 != 0 {
		return 0, fmt.Errorf("%w: %q: %v", errInterfaceNotFound, name, windows.Errno(r1))
	}
	if luid == 0 {
		return 0, fmt.Errorf("%w: %q", errInterfaceNotFound, name)
	}
	return luid, nil
}

// MIB_TCPROW (the MIB_TCPROW_LH layout): addresses as in_addr (network byte
// order in memory), ports in network byte order in the low 16 bits.
type mibTCPRow struct {
	state      uint32
	localAddr  uint32
	localPort  uint32
	remoteAddr uint32
	remotePort uint32
}

func (row mibTCPRow) local() netip.AddrPort {
	return netip.AddrPortFrom(rowAddr(row.localAddr), rowPort(row.localPort))
}

func (row mibTCPRow) remote() netip.Addr { return rowAddr(row.remoteAddr) }

func rowAddr(value uint32) netip.Addr {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], value) // memory order is network order
	return netip.AddrFrom4(bytes)
}

func rowPort(value uint32) uint16 {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], value)
	return binary.BigEndian.Uint16(bytes[:2])
}

// tcpTable returns the host's IPv4 TCP connections.
func tcpTable() ([]mibTCPRow, error) {
	if err := procGetTcpTable.Find(); err != nil {
		return nil, err
	}
	size := uint32(4096)
	for range 8 {
		buffer := make([]byte, size)
		r1, _, _ := procGetTcpTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0)
		switch windows.Errno(r1) {
		case 0:
			count := binary.LittleEndian.Uint32(buffer[:4])
			rowSize := uint32(unsafe.Sizeof(mibTCPRow{}))
			if uint64(4)+uint64(count)*uint64(rowSize) > uint64(len(buffer)) {
				return nil, fmt.Errorf("GetTcpTable: %d rows overflow a %d-byte table", count, len(buffer))
			}
			rows := make([]mibTCPRow, count)
			for index := range rows {
				rows[index] = *(*mibTCPRow)(unsafe.Pointer(&buffer[4+uint32(index)*rowSize]))
			}
			return rows, nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			size += 4096 // room for connections opened since the size was taken
		default:
			return nil, fmt.Errorf("GetTcpTable: %w", windows.Errno(r1))
		}
	}
	return nil, fmt.Errorf("GetTcpTable: table kept growing")
}

// resetTCPConnection deletes a connection's TCB, which sends the peer a RST.
// It needs an elevated process. A connection that already closed is not an
// error.
func resetTCPConnection(row mibTCPRow) error {
	if err := procSetTcpEntry.Find(); err != nil {
		return err
	}
	row.state = mibTCPStateDeleteTCB
	r1, _, _ := procSetTcpEntry.Call(uintptr(unsafe.Pointer(&row)))
	switch windows.Errno(r1) {
	case 0, windows.ERROR_NOT_FOUND:
		return nil
	default:
		return fmt.Errorf("SetTcpEntry %s -> %s: %w", row.remote(), row.local(), windows.Errno(r1))
	}
}

// tcpRowsMatching returns the established (non-listening) IPv4 TCP
// connections a removed rule had let in: local address and port are the
// rule's destination, the remote address its source (any source when the
// rule has none).
func tcpRowsMatching(rows []mibTCPRow, rule Rule) []mibTCPRow {
	if rule.Protocol != "tcp" || !rule.Destination.Unmap().Is4() {
		return nil
	}
	want := netip.AddrPortFrom(rule.Destination.Unmap(), rule.DestinationPort)
	var matched []mibTCPRow
	for _, row := range rows {
		if row.state == mibTCPStateListen || row.local() != want {
			continue
		}
		if rule.Source.IsValid() && row.remote() != rule.Source.Unmap() {
			continue
		}
		matched = append(matched, row)
	}
	return matched
}
