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
	"unsafe"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/byteorder"
)

// TupleKey6 represents the key for IPv6 entries in the local BPF conntrack map.
// Address field names are correct for return traffic, i.e., they are reversed
// compared to the original direction traffic.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type TupleKey6 struct {
	DestAddr   types.IPv6 `align:"daddr"`
	SourceAddr types.IPv6 `align:"saddr"`
	TupleKeyCommon
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *TupleKey6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

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

// GetDestAddr returns the destination IP address.
func (k *TupleKey6) GetDestAddr() types.IP {
	return k.DestAddr
}

// GetSourceAddr returns the source IP address.
func (k *TupleKey6) GetSourceAddr() types.IP {
	return k.SourceAddr
}

// String returns the tuple's string representation, doh.
func (k *TupleKey6) String() string {
	return fmt.Sprintf("[%s]:%d, %d, %d, %d", k.DestAddr, k.SourcePort, k.DestPort, k.NextHeader, k.Flags)
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
