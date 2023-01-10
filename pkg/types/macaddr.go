// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
)

// MACAddr is the binary representation for encoding in binary structs.
type MACAddr [6]byte

func (addr MACAddr) hardwareAddr() net.HardwareAddr {
	return addr[:]
}

func (addr MACAddr) String() string {
	return addr.hardwareAddr().String()
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (addr *MACAddr) DeepCopyInto(out *MACAddr) {
	copy(out[:], addr[:])
	return
}
