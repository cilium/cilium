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
	"bytes"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	TUPLE_F_OUT     = 0
	TUPLE_F_IN      = 1
	TUPLE_F_RELATED = 2
	TUPLE_F_SERVICE = 4
)

// TupleKey is the interface describing keys to the conntrack and NAT maps.
type TupleKey interface {
	bpf.MapKey

	// ToNetwork converts fields to network byte order.
	ToNetwork() TupleKey

	// ToHost converts fields to host byte order.
	ToHost() TupleKey

	// Returns flags containing the direction of the tuple key.
	GetFlags() uint8

	// GetDestAddr returns the destination IP address.
	GetDestAddr() types.IP

	// GetSourceAddr returns the source IP address.
	GetSourceAddr() types.IP

	// GetDestPort returns the destination port.
	GetDestPort() uint16

	// GetSourcePort returns the source port.
	GetSourcePort() uint16

	// GetNextHeader returns the next header.
	GetNextHeader() u8proto.U8proto
}

func Dump(k TupleKey, buffer *bytes.Buffer, reverse bool) bool {
	var addrDest string

	if k.GetNextHeader() == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrDest = k.GetSourceAddr().IP().String()
	} else {
		addrDest = k.GetDestAddr().IP().String()
	}

	if k.GetFlags()&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			k.GetNextHeader().String(), addrDest, k.GetSourcePort(),
			k.GetDestPort()),
		)
	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			k.GetNextHeader().String(), addrDest, k.GetDestPort(),
			k.GetSourcePort()),
		)
	}

	if k.GetFlags()&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	if k.GetFlags()&TUPLE_F_SERVICE != 0 {
		buffer.WriteString("service ")
	}

	return true
}

// TupleKeyCommon represents the common data for keys for IPv4 and IPv6 entries
// in the local BPF conntrack map.
type TupleKeyCommon struct {
	DestPort   uint16          `align:"dport"`
	SourcePort uint16          `align:"sport"`
	NextHeader u8proto.U8proto `align:"nexthdr"`
	Flags      uint8           `align:"flags"`
}

// NewValue creates a new bpf.MapValue.
func (k *TupleKeyCommon) NewValue() bpf.MapValue { return &TupleValStub{} }

// GetFlags returns the tuple's flags.
func (k *TupleKeyCommon) GetFlags() uint8 {
	return k.Flags
}

// GetDestPort returns the destination port.
func (k *TupleKeyCommon) GetDestPort() uint16 {
	return k.DestPort
}

// GetSourcePort returns the source port.
func (k *TupleKeyCommon) GetSourcePort() uint16 {
	return k.SourcePort
}

// GetNextHeader returns the next header.
func (k *TupleKeyCommon) GetNextHeader() u8proto.U8proto {
	return k.NextHeader
}

type buff256uint8 [256]uint8

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *buff256uint8) DeepCopyInto(out *buff256uint8) {
	copy(out[:], in[:])
	return
}

// TupleValStub is a dummy, unused.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type TupleValStub struct {
	buff buff256uint8
}

// GetValuePtr returns the unsafe.Pointer for s.
func (t *TupleValStub) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(t) }

// String stub method.
func (t *TupleValStub) String() string {
	return fmt.Sprintf("<TupleValStub>")
}
