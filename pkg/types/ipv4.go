// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
)

// IPv4 is the binary representation for encoding in binary structs.
type IPv4 [4]byte

func (v4 IPv4) IP() net.IP {
	return v4[:]
}

func (v4 IPv4) String() string {
	return v4.IP().String()
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (v4 *IPv4) DeepCopyInto(out *IPv4) {
	copy(out[:], v4[:])
	return
}
