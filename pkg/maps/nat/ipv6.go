// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nat

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
)

// NatEntry6 represents an IPv6 entry in the NAT table.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type NatEntry6 struct {
	Created   uint64     `align:"created"`
	HostLocal uint64     `align:"host_local"`
	Pad1      uint64     `align:"pad1"`
	Pad2      uint64     `align:"pad2"`
	Addr      types.IPv6 `align:"to_saddr"`
	Port      uint16     `align:"to_sport"`
}

// SizeofNatEntry6 is the size of the NatEntry6 type in bytes.
const SizeofNatEntry6 = int(unsafe.Sizeof(NatEntry6{}))

// GetValuePtr returns the unsafe.Pointer for n.
func (n *NatEntry6) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(n) }

// String returns the readable format.
func (n *NatEntry6) String() string {
	return fmt.Sprintf("Addr=%s Port=%d Created=%d HostLocal=%d\n",
		n.Addr,
		n.Port,
		n.Created,
		n.HostLocal)
}

// Dump dumps NAT entry to string.
func (n *NatEntry6) Dump(key NatKey, start uint64) string {
	var which string

	if key.GetFlags()&tuple.TUPLE_F_IN != 0 {
		which = "DST"
	} else {
		which = "SRC"
	}
	return fmt.Sprintf("XLATE_%s [%s]:%d Created=%s HostLocal=%d\n",
		which,
		n.Addr,
		n.Port,
		NatDumpCreated(start, n.Created),
		n.HostLocal)
}

// ToHost converts NatEntry4 ports to host byte order.
func (n *NatEntry6) ToHost() NatEntry {
	x := *n
	x.Port = byteorder.NetworkToHost(n.Port).(uint16)
	return &x
}
