// Copyright 2016-2018 Authors of Cilium
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

// CtKey4 represents the key for IPv4 entries in the BPF conntrack maps.
// Field names are correct for return traffic, i.e., they are reversed
// compared to the original direction traffic.
type CtKey4 struct {
	DestAddr   types.IPv4
	SourceAddr types.IPv4
	SourcePort uint16
	DestPort   uint16
	NextHeader u8proto.U8proto
	Flags      uint8
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

//NewValue creates a new bpf.MapValue.
func (k *CtKey4) NewValue() bpf.MapValue { return &CtEntry{} }

// ToNetwork converts CtKey4 ports to network byte order.
func (k *CtKey4) ToNetwork() CtKey {
	n := *k
	n.SourcePort = byteorder.HostToNetwork(n.SourcePort).(uint16)
	n.DestPort = byteorder.HostToNetwork(n.DestPort).(uint16)
	return &n
}

// ToHost converts CtKey4 ports to host byte order.
func (k *CtKey4) ToHost() CtKey {
	n := *k
	n.SourcePort = byteorder.NetworkToHost(n.SourcePort).(uint16)
	n.DestPort = byteorder.NetworkToHost(n.DestPort).(uint16)
	return &n
}

func (k *CtKey4) String() string {
	return fmt.Sprintf("%s:%d, %d, %d, %d", k.DestAddr, k.SourcePort, k.DestPort, k.NextHeader, k.Flags)
}

// Dump writes the contents of key to buffer and returns true if the value for
// next header in the key is nonzero.
func (k CtKey4) Dump(buffer *bytes.Buffer) bool {
	if k.NextHeader == 0 {
		return false
	}

	if k.Flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			k.NextHeader.String(),
			k.DestAddr.IP().String(),
			k.SourcePort, k.DestPort),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			k.NextHeader.String(),
			k.DestAddr.IP().String(),
			k.DestPort,
			k.SourcePort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		buffer.WriteString("service ")
	}

	return true
}

//CtKey4Global represents the key for IPv4 entries in the global BPF conntrack
// map.
type CtKey4Global struct {
	CtKey4
}

func (k *CtKey4Global) String() string {
	return fmt.Sprintf("%s:%d --> %s:%d, %d, %d", k.SourceAddr, k.SourcePort, k.DestAddr, k.DestPort, k.NextHeader, k.Flags)
}

// Dump writes the contents of key to buffer and returns true if the value for
// next header in the key is nonzero.
func (k CtKey4Global) Dump(buffer *bytes.Buffer) bool {
	if k.NextHeader == 0 {
		return false
	}

	if k.Flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s:%d -> %s:%d ",
			k.NextHeader.String(),
			k.SourceAddr.IP().String(), k.SourcePort,
			k.DestAddr.IP().String(), k.DestPort),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s:%d -> %s:%d ",
			k.NextHeader.String(),
			k.SourceAddr.IP().String(), k.SourcePort,
			k.DestAddr.IP().String(), k.DestPort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		buffer.WriteString("service ")
	}

	return true
}
