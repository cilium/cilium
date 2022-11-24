// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"net"
)

const macAddrSize = 6

// MACAddr is the binary representation for encoding in binary structs.
type MACAddr [macAddrSize]byte

func (addr MACAddr) hardwareAddr() net.HardwareAddr {
	return addr[:]
}

func (addr MACAddr) String() string {
	return addr.hardwareAddr().String()
}

func (addr MACAddr) MarshalText() ([]byte, error) {
	return []byte(addr.String()), nil
}

func (addr *MACAddr) UnmarshalText(text []byte) error {
	mac, err := net.ParseMAC(string(text))
	if err != nil {
		return err
	}
	// We only want to unmarshal addresses that are exactly
	// MacAddrs spec.
	if len(mac) != macAddrSize {
		return fmt.Errorf("parsed hardware addr must be of size %d", macAddrSize)
	}
	copy(addr[:], mac)
	return nil
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (addr *MACAddr) DeepCopyInto(out *MACAddr) {
	copy(out[:], addr[:])
}
