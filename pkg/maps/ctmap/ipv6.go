// Copyright 2016-2017 Authors of Cilium
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

package ctmap

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/u8proto"
)

//CtKey6 represents the key for IPv6 entries in the local BPF conntrack map.
type CtKey6 struct {
	daddr   types.IPv6
	saddr   types.IPv6
	sport   uint16
	dport   uint16
	nexthdr u8proto.U8proto
	flags   uint8
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

//NewValue creates a new bpf.MapValue.
func (k *CtKey6) NewValue() bpf.MapValue { return &CtEntry{} }

// Convert converts CtKey6 ports between host bye order and map byte order.
func (k *CtKey6) Convert() CtKey {
	n := *k
	n.sport = common.Swab16(n.sport)
	n.dport = common.Swab16(n.dport)
	return &n
}

func (k *CtKey6) String() string {
	return fmt.Sprintf("[%s]:%d, %d, %d, %d", k.daddr, k.sport, k.dport, k.nexthdr, k.flags)
}

// Dump writes the contents of key to buffer and returns true if the value for
// next header in the key is nonzero.
func (k CtKey6) Dump(buffer *bytes.Buffer) bool {
	if k.nexthdr == 0 {
		return false
	}

	if k.flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			k.nexthdr.String(),
			k.daddr.IP().String(),
			k.sport, k.dport),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			k.nexthdr.String(),
			k.daddr.IP().String(),
			k.dport,
			k.sport),
		)
	}

	if k.flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	return true
}

//CtKey6Global represents the key for IPv6 entries in the global BPF conntrack map.
type CtKey6Global struct {
	daddr   types.IPv6
	saddr   types.IPv6
	sport   uint16
	dport   uint16
	nexthdr u8proto.U8proto
	flags   uint8
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey6Global) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

//NewValue creates a new bpf.MapValue.
func (k *CtKey6Global) NewValue() bpf.MapValue { return &CtEntry{} }

// Convert converts CtKey6Global ports between host bye order and map byte order.
func (k *CtKey6Global) Convert() CtKey {
	n := *k
	n.sport = common.Swab16(n.sport)
	n.dport = common.Swab16(n.dport)
	return &n
}

func (k *CtKey6Global) String() string {
	return fmt.Sprintf("[%s]:%d --> [%s]:%d, %d, %d", k.saddr, k.sport, k.daddr, k.dport, k.nexthdr, k.flags)
}

// Dump writes the contents of key to buffer and returns true if the value for
// next header in the key is nonzero.
func (k CtKey6Global) Dump(buffer *bytes.Buffer) bool {
	if k.nexthdr == 0 {
		return false
	}

	if k.flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN [%s]:%d -> [%s]:%d ",
			k.nexthdr.String(),
			k.saddr.IP().String(), k.sport,
			k.daddr.IP().String(), k.dport),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT [%s]:%d -> [%s]:%d ",
			k.nexthdr.String(),
			k.saddr.IP().String(), k.sport,
			k.daddr.IP().String(), k.dport),
		)
	}

	if k.flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	return true
}
