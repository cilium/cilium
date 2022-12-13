// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"fmt"
	"unsafe"

	natTypes "github.com/cilium/cilium/pkg/maps/nat/types"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/tuple"
)

// NatEntry4 represents an IPv4 entry in the NAT table.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapValue
type NatEntry4 natTypes.NatEntry4

// SizeofNatEntry4 is the size of the NatEntry4 type in bytes.
const SizeofNatEntry4 = int(unsafe.Sizeof(NatEntry4{}))

// GetValuePtr returns the unsafe.Pointer for n.
func (n *NatEntry4) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(n) }

// String returns the readable format.
func (n *NatEntry4) String() string {
	return fmt.Sprintf("Addr=%s Port=%d Created=%d HostLocal=%d\n",
		n.Addr,
		n.Port,
		n.Created,
		n.HostLocal)
}

// Dump dumps NAT entry to string.
func (n *NatEntry4) Dump(key NatKey, start uint64) string {
	var which string

	if key.GetFlags()&tuple.TUPLE_F_IN != 0 {
		which = "DST"
	} else {
		which = "SRC"
	}
	return fmt.Sprintf("XLATE_%s %s:%d Created=%s HostLocal=%d\n",
		which,
		n.Addr,
		n.Port,
		NatDumpCreated(start, n.Created),
		n.HostLocal)
}

// ToHost converts NatEntry4 ports to host byte order.
func (n *NatEntry4) ToHost() NatEntry {
	x := *n
	x.Port = byteorder.NetworkToHost16(n.Port)
	return &x
}
