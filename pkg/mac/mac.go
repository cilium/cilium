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

// MAC is an IEEE 802 MAC-48 address.
//
// It is a comparable value type: two MACs may be compared with == and a MAC may
// be used as a map key. Its zero value means "unset", which is how a device
// carrying no layer 2 address, such as an L3/NOARP device, is represented.
type MAC [6]byte

// String returns the string representation of m, or the empty string if m is
// unset.
func (m MAC) String() string {
	if !m.IsValid() {
		return ""
	}
	return m.HardwareAddr().String()
}

// IsValid reports whether m is set. Devices without a layer 2 address, such as
// L3/NOARP devices, carry an invalid MAC.
func (m MAC) IsValid() bool {
	return m != MAC{}
}

// HardwareAddr returns m as a [net.HardwareAddr], or nil if m is unset. The
// result is a copy and does not alias m.
//
// Unset must map to nil rather than to six zero bytes: consumers such as
// netlink treat a nil [net.HardwareAddr] as "no address requested" and a
// non-nil one as an explicit address to set, which the kernel rejects for
// devices that carry no layer 2 address.
func (m MAC) HardwareAddr() net.HardwareAddr {
	if !m.IsValid() {
		return nil
	}
	return net.HardwareAddr(m[:])
}

// ParseMAC parses s only as an IEEE 802 MAC-48.
func ParseMAC(s string) (MAC, error) {
	ha, err := net.ParseMAC(s)
	if err != nil {
		return MAC{}, err
	}
	// MAC only supports the IEEE 802 MAC-48 address format while [net.HardwareAddress]
	// supports several other formats, see [net.ParseMAC].
	if len(ha) != 6 {
		return MAC{}, fmt.Errorf("invalid MAC address %s", s)
	}

	return MAC(ha), nil
}

// FromHardwareAddr converts ha to a MAC. Like [ParseMAC] it only accepts an
// IEEE 802 MAC-48 address, so a device carrying no layer 2 address, such as an
// L3/NOARP device, yields an error rather than an unset MAC.
//
// Prefer this over a plain MAC(ha) conversion, which panics at run time on a
// [net.HardwareAddr] shorter than 6 bytes.
func FromHardwareAddr(ha net.HardwareAddr) (MAC, error) {
	if len(ha) != 6 {
		return MAC{}, fmt.Errorf("invalid MAC address %q", ha)
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
//	m := MAC{0x11, 0x12, 0x23, 0x34, 0x45, 0x56}
//	fmt.Printf("0x%X", m.Uint64()) // 0x564534231211
func (m MAC) Uint64() Uint64MAC {
	res := uint64(m[5])<<40 | uint64(m[4])<<32 | uint64(m[3])<<24 |
		uint64(m[2])<<16 | uint64(m[1])<<8 | uint64(m[0])
	return Uint64MAC(res)
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
		*m = hw
	}
	return err
}

// GenerateRandMAC generates a random unicast and locally administered MAC address.
func GenerateRandMAC() (MAC, error) {
	var m MAC
	if _, err := rand.Read(m[:]); err != nil {
		return MAC{}, fmt.Errorf("Unable to retrieve 6 rnd bytes: %w", err)
	}

	// Set locally administered addresses bit and reset multicast bit
	m[0] = (m[0] | 0x02) & 0xfe

	return m, nil
}
