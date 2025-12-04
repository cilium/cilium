// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighborsmap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// map4Name is the BPF map name.
	map4Name = "cilium_nodeport_neigh4"
	// map6Name is the BPF map name.
	map6Name = "cilium_nodeport_neigh6"
)

// Map is a marker interface for the neighbors map.
// It doesn't provide any functionality to the Cilium Agent because
// the bpf map is only created by the Cilium Agent for the datapath.
// It's still provided to be picked up as dependency by the Loader
// and initialized at startup.
type Map any

type neighborsMap struct {
	bpfMapV4 *bpf.Map
	bpfMapV6 *bpf.Map
}

func newMap(maxMapEntries int, ipv4Enabled bool, ipv6Enabled bool) *neighborsMap {
	m := &neighborsMap{}

	if ipv4Enabled {
		m.bpfMapV4 = bpf.NewMap(map4Name,
			ebpf.LRUHash,
			&Key4{},
			&Value{},
			maxMapEntries,
			0,
		)
	}

	if ipv6Enabled {
		m.bpfMapV6 = bpf.NewMap(map6Name,
			ebpf.LRUHash,
			&Key6{},
			&Value{},
			maxMapEntries,
			0,
		)
	}

	return m
}

func (m *neighborsMap) init() error {
	if m.bpfMapV4 != nil {
		if err := m.bpfMapV4.Create(); err != nil {
			return fmt.Errorf("failed to create neighbors v4 bpf map: %w", err)
		}
	}

	if m.bpfMapV6 != nil {
		if err := m.bpfMapV6.Create(); err != nil {
			return fmt.Errorf("failed to create neighbors v6 bpf map: %w", err)
		}
	}

	return nil
}

// Key4 is the IPv4 for the IP-to-MAC address mappings.
type Key4 struct {
	Ipv4 types.IPv4
}

// Key6 is the IPv6 for the IP-to-MAC address mappings.
type Key6 struct {
	Ipv6 types.IPv6
}

// SizeofNeighKey6 is the size of type NeighKey6.
const SizeofNeighKey6 = int(unsafe.Sizeof(Key6{}))

// Value is the MAC address for the IP-to-MAC address mappings.
type Value struct {
	Macaddr types.MACAddr
	_       uint16
}

// SizeOfNeighValue is the size of type NeighValue.
const SizeOfNeighValue = int(unsafe.Sizeof(Value{}))

// String converts the key into a human readable string format.
func (k *Key4) String() string { return k.Ipv4.String() }

func (k *Key4) New() bpf.MapKey { return &Key4{} }

// String converts the key into a human readable string format.
func (k *Key6) String() string { return k.Ipv6.String() }

func (k *Key6) New() bpf.MapKey { return &Key6{} }

// String converts the value into a human readable string format.
func (v *Value) String() string { return v.Macaddr.String() }

func (v *Value) New() bpf.MapValue { return &Value{} }
