// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2019 Authors of Cilium

package types

import (
	"net"
)

// IPv6 is the binary representation for encoding in binary structs.
type IPv6 [16]byte

func (v6 IPv6) IP() net.IP {
	return v6[:]
}

func (v6 IPv6) String() string {
	return v6.IP().String()
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (v6 *IPv6) DeepCopyInto(out *IPv6) {
	copy(out[:], v6[:])
	return
}
