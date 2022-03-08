// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mac

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// Untagged ethernet (IEEE 802.3) frame header len
const EthHdrLen = 14

// MAC address is an net.HardwareAddr encapsulation to force cilium to only use MAC-48.
type MAC net.HardwareAddr

// String returns the string representation of m.
func (m MAC) String() string {
	return net.HardwareAddr(m).String()
}

// ParseMAC parses s only as an IEEE 802 MAC-48.
func ParseMAC(s string) (MAC, error) {
	ha, err := net.ParseMAC(s)
	if err != nil {
		return nil, err
	}
	if len(ha) != 6 {
		return nil, fmt.Errorf("invalid MAC address %s", s)
	}

	return MAC(ha), nil
}

// Uint64 returns the MAC in uint64 format. The MAC is represented as little-endian in
// the returned value.
// Example:
//  m := MAC([]{0x11, 0x12, 0x23, 0x34, 0x45, 0x56})
//  v, err := m.Uint64()
//  fmt.Printf("0x%X", v) // 0x564534231211
func (m MAC) Uint64() (uint64, error) {
	if len(m) != 6 {
		return 0, fmt.Errorf("invalid MAC address %s", m.String())
	}

	return uint64(m[5])<<40 | uint64(m[4])<<32 | uint64(m[3])<<24 |
		uint64(m[2])<<16 | uint64(m[1])<<8 | uint64(m[0]), nil
}

func (m MAC) MarshalJSON() ([]byte, error) {
	if len(m) == 0 {
		return []byte(`""`), nil
	}
	if len(m) != 6 {
		return nil, fmt.Errorf("invalid MAC address length %s", string(m))
	}
	return []byte(fmt.Sprintf("\"%02x:%02x:%02x:%02x:%02x:%02x\"", m[0], m[1], m[2], m[3], m[4], m[5])), nil
}

func (m MAC) MarshalIndentJSON(prefix, indent string) ([]byte, error) {
	return m.MarshalJSON()
}

func (m *MAC) UnmarshalJSON(data []byte) error {
	if len(data) == len([]byte(`""`)) {
		if m == nil {
			m = new(MAC)
		}
		*m = MAC{}
		return nil
	}
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
	*m = MAC{macByte[0], macByte[1], macByte[2], macByte[3], macByte[4], macByte[5]}
	return nil
}

// GenerateRandMAC generates a random unicast and locally administered MAC address.
func GenerateRandMAC() (MAC, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("Unable to retrieve 6 rnd bytes: %s", err)
	}

	// Set locally administered addresses bit and reset multicast bit
	buf[0] = (buf[0] | 0x02) & 0xfe

	return MAC(buf), nil
}

// HasMacAddr returns true if the given network interface has L2 addr.
func HasMacAddr(iface string) bool {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return false
	}
	return LinkHasMacAddr(link)
}

// LinkHasMacAddr returns true if the given network interface has L2 addr.
func LinkHasMacAddr(link netlink.Link) bool {
	return len(link.Attrs().HardwareAddr) != 0
}

// HaveMACAddrs returns true if all given network interfaces have L2 addr.
func HaveMACAddrs(ifaces []string) bool {
	for _, iface := range ifaces {
		if !HasMacAddr(iface) {
			return false
		}
	}
	return true
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
