package types

import (
	"bytes"
	"encoding/hex"
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

func (m MAC) MarshalJSON() ([]byte, error) {
	// FIXME: mac can be empty
	if len(m) != 6 {
		return nil, fmt.Errorf("invalid MAC address length %s", string(m))
	}
	return []byte(fmt.Sprintf("\"%02x:%02x:%02x:%02x:%02x:%02x\"", m[0], m[1], m[2], m[3], m[4], m[5])), nil
}

func (m MAC) MarshalIndentJSON(prefix, indent string) ([]byte, error) {
	return m.MarshalJSON()
}

func (m *MAC) UnmarshalJSON(data []byte) error {
	if len(data) != 19 {
		return fmt.Errorf("invalid MAC address length %s", string(data))
	}
	data = data[1 : len(data)-1]
	macStr := bytes.Replace(data, []byte(`:`), []byte(``), -1)
	if len(macStr) != 12 {
		return fmt.Errorf("invalid MAC address format")
	}
	macByte := make([]byte, len(macStr))
	hex.Decode(macByte, macStr)
	if m == nil {
		m = new(MAC)
	}
	*m = MAC{macByte[0], macByte[1], macByte[2], macByte[3], macByte[4], macByte[5]}
	return nil
}
