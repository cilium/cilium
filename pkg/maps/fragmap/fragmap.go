// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fragmap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// MapName is the name of the map used to retrieve L4 ports associated
	// to the datagram to which an IPv4 belongs.
	MapName = "cilium_ipv4_frag_datagrams"
)

// FragmentKey must match 'struct ipv4_frag_id' in "bpf/lib/ipv4.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type FragmentKey struct {
	destAddr   types.IPv4 `align:"daddr"`
	sourceAddr types.IPv4 `align:"saddr"`
	id         uint16     `align:"id"`
	proto      uint8      `align:"proto"`
	pad        uint8      `align:"pad"`
}

// FragmentValue must match 'struct ipv4_frag_l4ports' in "bpf/lib/ipv4.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type FragmentValue struct {
	sourcePort uint16 `align:"sport"`
	destPort   uint16 `align:"dport"`
}

// GetKeyPtr returns the unsafe pointer to the BPF key.
func (k *FragmentKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *FragmentValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format.
func (k *FragmentKey) String() string {
	return fmt.Sprintf("%s --> %s, %d, %d", k.sourceAddr, k.destAddr, k.proto, k.id)
}

// String converts the value into a human readable string format.
func (v *FragmentValue) String() string {
	return fmt.Sprintf("%d, %d", v.destPort, v.sourcePort)
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k FragmentKey) NewValue() bpf.MapValue { return &FragmentValue{} }

// InitMap creates the signal map in the kernel.
func InitMap(mapEntries int) error {
	fragMap := bpf.NewMap(MapName,
		bpf.MapTypeLRUHash,
		&FragmentKey{},
		int(unsafe.Sizeof(FragmentKey{})),
		&FragmentValue{},
		int(unsafe.Sizeof(FragmentValue{})),
		mapEntries,
		0,
		bpf.ConvertKeyValue,
	).WithEvents(option.Config.GetEventBufferConfig(MapName))
	return fragMap.Create()
}
