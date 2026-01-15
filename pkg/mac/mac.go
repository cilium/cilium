// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mac

import (
	"crypto/rand"
	"fmt"
	"net"
)

// Untagged ethernet (IEEE 802.3) frame header len
const EthHdrLen = 14

// Uint64MAC is the __u64 representation of a MAC address.
// It corresponds to the C mac_t type used in bpf/.
type Uint64MAC uint64

func (m Uint64MAC) String() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		uint64((m & 0x0000000000FF)),
		uint64((m&0x00000000FF00)>>8),
		uint64((m&0x000000FF0000)>>16),
		uint64((m&0x0000FF000000)>>24),
		uint64((m&0x00FF00000000)>>32),
		uint64((m&0xFF0000000000)>>40),
	)
}

// MAC address is an net.HardwareAddr encapsulation to force cilium to only use MAC-48.
type MAC net.HardwareAddr

// String returns the string representation of m.
func (m MAC) String() string {
	return net.HardwareAddr(m).String()
}

// As8 returns the MAC as an array of 8 bytes for use in datapath configuration
// structs. This is 8 bytes due to padding of union macaddr.
func (m MAC) As8() [8]byte {
	var res [8]byte
	copy(res[:], m)
	return res
}

// ParseMAC parses s only as an IEEE 802 MAC-48.
func ParseMAC(s string) (MAC, error) {
	ha, err := net.ParseMAC(s)
	if err != nil {
		return nil, err
	}
	// MAC only supports the IEEE 802 MAC-48 address format while [net.HardwareAddress]
	// supports several other formats, see [net.ParseMAC].
	if len(ha) != 6 {
		return nil, fmt.Errorf("invalid MAC address %s", s)
	}

	return MAC(ha), nil
}

// MustParseMAC calls [ParseMAC] and panics on error. It is intended for use in tests with
// hard-coded strings.
func MustParseMAC(s string) MAC {
	mac, err := ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}

// Uint64 returns the MAC in uint64 format. The MAC is represented as little-endian in
// the returned value.
// Example:
//
//	m := MAC([]{0x11, 0x12, 0x23, 0x34, 0x45, 0x56})
//	v, err := m.Uint64()
//	fmt.Printf("0x%X", v) // 0x564534231211
func (m MAC) Uint64() (Uint64MAC, error) {
	if len(m) != 6 {
		return 0, fmt.Errorf("invalid MAC address %s", m.String())
	}

	res := uint64(m[5])<<40 | uint64(m[4])<<32 | uint64(m[3])<<24 |
		uint64(m[2])<<16 | uint64(m[1])<<8 | uint64(m[0])
	return Uint64MAC(res), nil
}

// MarshalText implements the [encoding.TextMarshaler] interface.
// The encoding is the same as the one returned by [MAC.String].
func (m MAC) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (m *MAC) UnmarshalText(data []byte) error {
	if len(data) == 0 {
		*m = MAC{}
		return nil
	}
	hw, err := ParseMAC(string(data))
	if err == nil {
		*m = MAC(hw)
	}
	return err
}

// GenerateRandMAC generates a random unicast and locally administered MAC address.
func GenerateRandMAC() (MAC, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("Unable to retrieve 6 rnd bytes: %w", err)
	}

	// Set locally administered addresses bit and reset multicast bit
	buf[0] = (buf[0] | 0x02) & 0xfe

	return buf, nil
}

// CArrayString returns a string which can be used for assigning the given
// MAC addr to "union macaddr" in C.
func CArrayString(m net.HardwareAddr) string {
	if m == nil || len(m) != 6 {
		return "{0x0,0x0,0x0,0x0,0x0,0x0}"
	}

	return fmt.Sprintf("{0x%x,0x%x,0x%x,0x%x,0x%x,0x%x}",
		m[0], m[1], m[2], m[3], m[4], m[5])
}
