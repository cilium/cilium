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

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/u8proto"
)

//CtKey4 represents the key for IPv4 entries in the local BPF conntrack map.
type CtKey4 struct {
	daddr   types.IPv4
	saddr   types.IPv4
	sport   uint16
	dport   uint16
	nexthdr u8proto.U8proto
	flags   uint8
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

//NewValue creates a new bpf.MapValue.
func (k *CtKey4) NewValue() bpf.MapValue { return &CtEntry{} }

// ToNetwork converts CtKey4 ports to network byte order.
func (k *CtKey4) ToNetwork() CtKey {
	n := *k
	n.sport = byteorder.HostToNetwork(n.sport).(uint16)
	n.dport = byteorder.HostToNetwork(n.dport).(uint16)
	return &n
}

// ToHost converts CtKey4 ports to host byte order.
func (k *CtKey4) ToHost() CtKey {
	n := *k
	n.sport = byteorder.NetworkToHost(n.sport).(uint16)
	n.dport = byteorder.NetworkToHost(n.dport).(uint16)
	return &n
}

func (k *CtKey4) String() string {
	return fmt.Sprintf("%s:%d, %d, %d, %d", k.daddr, k.sport, k.dport, k.nexthdr, k.flags)
}

// Dump writes the contents of key to buffer and returns true if the value for
// next header in the key is nonzero.
func (k CtKey4) Dump(buffer *bytes.Buffer) bool {
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

//CtKey4Global represents the key for IPv4 entries in the global BPF conntrack
// map.
type CtKey4Global struct {
	daddr types.IPv4
	saddr types.IPv4
	// sport is in network byte order
	sport uint16
	// dport is in network byte order
	dport   uint16
	nexthdr u8proto.U8proto
	flags   uint8
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey4Global) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

//NewValue creates a new bpf.MapValue.
func (k *CtKey4Global) NewValue() bpf.MapValue { return &CtEntry{} }

// ToNetwork converts CtKey4Global ports to network byte order.
func (k *CtKey4Global) ToNetwork() CtKey {
	n := *k
	n.sport = byteorder.HostToNetwork(n.sport).(uint16)
	n.dport = byteorder.HostToNetwork(n.dport).(uint16)
	return &n
}

// ToHost converts CtKey4Global ports to host byte order.
func (k *CtKey4Global) ToHost() CtKey {
	n := *k
	n.sport = byteorder.NetworkToHost(n.sport).(uint16)
	n.dport = byteorder.NetworkToHost(n.dport).(uint16)
	return &n
}

func (k *CtKey4Global) String() string {
	return fmt.Sprintf("%s:%d --> %s:%d, %d, %d", k.saddr, k.sport, k.daddr, k.dport, k.nexthdr, k.flags)
}

// Dump writes the contents of key to buffer and returns true if the value for
// next header in the key is nonzero.
func (k CtKey4Global) Dump(buffer *bytes.Buffer) bool {
	if k.nexthdr == 0 {
		return false
	}

	if k.flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s:%d -> %s:%d ",
			k.nexthdr.String(),
			k.saddr.IP().String(), k.sport,
			k.daddr.IP().String(), k.dport),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s:%d -> %s:%d ",
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
