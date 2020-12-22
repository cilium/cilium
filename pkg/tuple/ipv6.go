// Copyright 2016-2019 Authors of Cilium
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

package tuple

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// TupleKey6 represents the key for IPv6 entries in the local BPF conntrack map.
// Address field names are correct for return traffic, i.e., they are reversed
// compared to the original direction traffic.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type TupleKey6 struct {
	DestAddr   types.IPv6      `align:"daddr"`
	SourceAddr types.IPv6      `align:"saddr"`
	DestPort   uint16          `align:"dport"`
	SourcePort uint16          `align:"sport"`
	NextHeader u8proto.U8proto `align:"nexthdr"`
	Flags      uint8           `align:"flags"`
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *TupleKey6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewValue creates a new bpf.MapValue.
func (k *TupleKey6) NewValue() bpf.MapValue { return &TupleValStub{} }

// ToNetwork converts TupleKey6 ports to network byte order.
func (k *TupleKey6) ToNetwork() TupleKey {
	n := *k
	n.SourcePort = byteorder.HostToNetwork(n.SourcePort).(uint16)
	n.DestPort = byteorder.HostToNetwork(n.DestPort).(uint16)
	return &n
}

// ToHost converts TupleKey6 ports to network byte order.
func (k *TupleKey6) ToHost() TupleKey {
	n := *k
	n.SourcePort = byteorder.NetworkToHost(n.SourcePort).(uint16)
	n.DestPort = byteorder.NetworkToHost(n.DestPort).(uint16)
	return &n
}

// GetFlags returns the tuple's flags.
func (k *TupleKey6) GetFlags() uint8 {
	return k.Flags
}

// String returns the tuple's string representation, doh.
func (k *TupleKey6) String() string {
	return fmt.Sprintf("[%s]:%d, %d, %d, %d", k.DestAddr, k.SourcePort, k.DestPort, k.NextHeader, k.Flags)
}

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k TupleKey6) Dump(sb *strings.Builder, reverse bool) bool {
	var addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrDest = k.SourceAddr.IP().String()
	} else {
		addrDest = k.DestAddr.IP().String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			k.NextHeader.String(), addrDest, k.SourcePort,
			k.DestPort),
		)
	} else {
		sb.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			k.NextHeader.String(), addrDest, k.DestPort,
			k.SourcePort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString("service ")
	}

	return true
}

// TupleKey6Global represents the key for IPv6 entries in the global BPF conntrack map.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type TupleKey6Global struct {
	TupleKey6
}

// GetFlags returns the tuple's flags.
func (k *TupleKey6Global) GetFlags() uint8 {
	return k.Flags
}

// String returns the tuple's string representation, doh.
func (k *TupleKey6Global) String() string {
	return fmt.Sprintf("[%s]:%d --> [%s]:%d, %d, %d", k.SourceAddr, k.SourcePort, k.DestAddr, k.DestPort, k.NextHeader, k.Flags)
}

// ToNetwork converts ports to network byte order.
//
// This is necessary to prevent callers from implicitly converting
// the TupleKey6Global type here into a local key type in the nested
// TupleKey6 field.
func (k *TupleKey6Global) ToNetwork() TupleKey {
	return &TupleKey6Global{
		TupleKey6: *k.TupleKey6.ToNetwork().(*TupleKey6),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the TupleKey6Global type here into a local key type in the nested
// TupleKey6 field.
func (k *TupleKey6Global) ToHost() TupleKey {
	return &TupleKey6Global{
		TupleKey6: *k.TupleKey6.ToHost().(*TupleKey6),
	}
}

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k TupleKey6Global) Dump(sb *strings.Builder, reverse bool) bool {
	var addrSource, addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrSource = k.DestAddr.IP().String()
		addrDest = k.SourceAddr.IP().String()
	} else {
		addrSource = k.SourceAddr.IP().String()
		addrDest = k.DestAddr.IP().String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(fmt.Sprintf("%s IN [%s]:%d -> [%s]:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	} else {
		sb.WriteString(fmt.Sprintf("%s OUT [%s]:%d -> [%s]:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString("service ")
	}

	return true
}
