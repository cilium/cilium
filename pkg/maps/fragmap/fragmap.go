// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fragmap

import (
	"fmt"

	"github.com/cilium/ebpf"

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
type FragmentKey struct {
	DestAddr   types.IPv4 `align:"daddr"`
	SourceAddr types.IPv4 `align:"saddr"`
	ID         uint16     `align:"id"`
	Proto      uint8      `align:"proto"`
	_          uint8
}

// FragmentValue must match 'struct ipv4_frag_l4ports' in "bpf/lib/ipv4.h".
type FragmentValue struct {
	SourcePort uint16 `align:"sport"`
	DestPort   uint16 `align:"dport"`
}

// String converts the key into a human-readable string format.
func (k *FragmentKey) String() string {
	return fmt.Sprintf("%s --> %s, %d, %d", k.SourceAddr, k.DestAddr, k.Proto, k.ID)
}

func (k *FragmentKey) New() bpf.MapKey { return &FragmentKey{} }

// String converts the value into a human-readable string format.
func (v *FragmentValue) String() string {
	return fmt.Sprintf("%d, %d", v.DestPort, v.SourcePort)
}

func (v *FragmentValue) New() bpf.MapValue { return &FragmentValue{} }

// InitMap creates the signal map in the kernel.
func InitMap(mapEntries int) error {
	fragMap := bpf.NewMap(MapName,
		ebpf.LRUHash,
		&FragmentKey{},
		&FragmentValue{},
		mapEntries,
		0,
	).WithEvents(option.Config.GetEventBufferConfig(MapName))
	return fragMap.Create()
}

// OpenMap opens the pre-initialized fragments map for access.
func OpenMap() (*bpf.Map, error) {
	return bpf.OpenMap(bpf.MapPath(MapName), &FragmentKey{}, &FragmentValue{})
}
