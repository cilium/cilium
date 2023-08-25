// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
)

// NatEntry6 represents an IPv6 entry in the NAT table.
type NatEntry6 struct {
	Created uint64     `align:"created"`
	NeedsCT uint64     `align:"needs_ct"`
	Pad1    uint64     `align:"pad1"`
	Pad2    uint64     `align:"pad2"`
	Addr    types.IPv6 `align:"to_saddr"`
	Port    uint16     `align:"to_sport"`
	_       [6]byte
}

// SizeofNatEntry6 is the size of the NatEntry6 type in bytes.
const SizeofNatEntry6 = int(unsafe.Sizeof(NatEntry6{}))

// String returns the readable format.
func (n *NatEntry6) String() string {
	return fmt.Sprintf("Addr=%s Port=%d Created=%d NeedsCT=%d\n",
		n.Addr,
		n.Port,
		n.Created,
		n.NeedsCT)
}

// Dump dumps NAT entry to string.
func (n *NatEntry6) Dump(key NatKey, start uint64) string {
	var which string

	if key.GetFlags()&tuple.TUPLE_F_IN != 0 {
		which = "DST"
	} else {
		which = "SRC"
	}
	return fmt.Sprintf("XLATE_%s [%s]:%d Created=%s NeedsCT=%d\n",
		which,
		n.Addr,
		n.Port,
		NatDumpCreated(start, n.Created),
		n.NeedsCT)
}

// ToHost converts NatEntry4 ports to host byte order.
func (n *NatEntry6) ToHost() NatEntry {
	x := *n
	x.Port = byteorder.NetworkToHost16(n.Port)
	return &x
}

func (n *NatEntry6) New() bpf.MapValue { return &NatEntry6{} }
