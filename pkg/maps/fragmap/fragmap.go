// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fragmap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	bpfTypes "github.com/cilium/cilium/pkg/bpf/types"
	fragmapTypes "github.com/cilium/cilium/pkg/maps/fragmap/types"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// MapName is the name of the map used to retrieve L4 ports associated
	// to the datagram to which an IPv4 belongs.
	MapName = "cilium_ipv4_frag_datagrams"
)

// FragmentKey must match 'struct ipv4_frag_id' in "bpf/lib/ipv4.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapKey
type FragmentKey fragmapTypes.FragmentKey

// FragmentValue must match 'struct ipv4_frag_l4ports' in "bpf/lib/ipv4.h".
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf/types.MapValue
type FragmentValue fragmapTypes.FragmentValue

// GetKeyPtr returns the unsafe pointer to the BPF key.
func (k *FragmentKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *FragmentValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format.
func (k *FragmentKey) String() string {
	return fmt.Sprintf("%s --> %s, %d, %d", k.SourceAddr, k.DestAddr, k.Proto, k.Id)
}

// String converts the value into a human readable string format.
func (v *FragmentValue) String() string {
	return fmt.Sprintf("%d, %d", v.DestPort, v.SourcePort)
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k FragmentKey) NewValue() bpfTypes.MapValue { return &FragmentValue{} }

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
		0,
		bpf.ConvertKeyValue,
	).WithEvents(option.Config.GetEventBufferConfig(MapName))
	_, err := fragMap.Create()
	return err
}
