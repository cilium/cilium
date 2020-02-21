// Copyright 2020 Authors of Cilium
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

package neighborsmap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// Map4Name is the BPF map name.
	Map4Name = "cilium_nodeport_neigh4"
	// Map6Name is the BPF map name.
	Map6Name = "cilium_nodeport_neigh6"
)

// Key4 is the IPv4 for the IP-to-MAC address mappings.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key4 struct {
	ipv4 types.IPv4
}

// Key6 is the IPv6 for the IP-to-MAC address mappings.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key6 struct {
	ipv6 types.IPv6
}

// Value is the MAC address for the IP-to-MAC address mappings.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Value struct {
	macaddr types.MACAddr
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format.
func (k *Key4) String() string { return fmt.Sprintf("%s", k.ipv4) }

// String converts the key into a human readable string format.
func (k *Key6) String() string { return fmt.Sprintf("%s", k.ipv6) }

// String converts the value into a human readable string format.
func (v *Value) String() string { return fmt.Sprintf("%s", v.macaddr) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k Key4) NewValue() bpf.MapValue { return &Value{} }

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k Key6) NewValue() bpf.MapValue { return &Value{} }

// InitMaps creates the nodeport neighbors maps in the kernel.
func InitMaps(ipv4, ipv6 bool) error {
	if ipv4 {
		neighbors4Map := bpf.NewMap(Map4Name,
			bpf.MapTypeLRUHash,
			&Key4{},
			int(unsafe.Sizeof(Key4{})),
			&Value{},
			int(unsafe.Sizeof(Value{})),
			option.Config.NATMapEntriesGlobal,
			0,
			0,
			bpf.ConvertKeyValue,
		)
		if _, err := neighbors4Map.Create(); err != nil {
			return err
		}
	}
	if ipv6 {
		neighbors6Map := bpf.NewMap(Map6Name,
			bpf.MapTypeLRUHash,
			&Key6{},
			int(unsafe.Sizeof(Key4{})),
			&Value{},
			int(unsafe.Sizeof(Value{})),
			option.Config.NATMapEntriesGlobal,
			0,
			0,
			bpf.ConvertKeyValue,
		)
		if _, err := neighbors6Map.Create(); err != nil {
			return err
		}
	}
	return nil
}
