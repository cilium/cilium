// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighborsmap

import (
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// Map4Name is the BPF map name.
	Map4Name = "cilium_nodeport_neigh4"
	// Map6Name is the BPF map name.
	Map6Name = "cilium_nodeport_neigh6"
)

type NeighborsMap struct {
	IPv4Map *bpf.Map
	IPv6Map *bpf.Map
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
func (k *Key4) String() string  { return k.Ipv4.String() }
func (k *Key4) New() bpf.MapKey { return &Key4{} }

// String converts the key into a human readable string format.
func (k *Key6) String() string  { return k.Ipv6.String() }
func (k *Key6) New() bpf.MapKey { return &Key6{} }

// String converts the value into a human readable string format.
func (v *Value) String() string    { return v.Macaddr.String() }
func (k *Value) New() bpf.MapValue { return &Value{} }

// NeighRetire retires a cached neigh entry from the LRU cache
func (nm *NeighborsMap) NeighRetire(ip net.IP) {
	if len(ip) == net.IPv4len {
		key := &Key4{}
		copy(key.Ipv4[:], ip.To4())
		nm.IPv4Map.Delete(key)
	} else {
		key := &Key6{}
		copy(key.Ipv6[:], ip.To16())
		nm.IPv6Map.Delete(key)
	}
}
