package types

import (
	"fmt"
	"net"
)

// MAC address is an net.HardwareAddr encapsulation to force cilium to only use MAC-48.
type MAC net.HardwareAddr

// String returns the string representation of m.
func (m MAC) String() string {
	return net.HardwareAddr(m).String()
}

// Uint64 returns the MAC in uint64 format. The MAC is represented as little-endian in
// the returned value.
// Example:
//  m := MAC([]{0x11, 0x12, 0x23, 0x34, 0x45, 0x56})
//  v, err := m.Uint64()
//  fmt.Printf("0x%X", v) // 0x564534231211
func (m MAC) Uint64() (uint64, error) {
	if len(m) != 6 {
		return 0, fmt.Errorf("Invalid MAC address %s", m.String())
	}

	return uint64(uint64(m[5])<<40 | uint64(m[4])<<32 | uint64(m[3])<<24 |
		uint64(m[2])<<16 | uint64(m[1])<<8 | uint64(m[0])), nil
}
