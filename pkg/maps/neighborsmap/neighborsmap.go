// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighborsmap

import (
	"net"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// Map4Name is the BPF map name.
	Map4Name = "cilium_nodeport_neigh4"
	// Map6Name is the BPF map name.
	Map6Name = "cilium_nodeport_neigh6"
)

var (
	neigh4Map *bpf.Map
	neigh6Map *bpf.Map
	once      sync.Once
)

func neighMapsGet() (*bpf.Map, *bpf.Map) {
	once.Do(func() {
		neigh4Map = bpf.NewMap(Map4Name,
			bpf.MapTypeLRUHash,
			&Key4{},
			int(unsafe.Sizeof(Key4{})),
			&Value{},
			int(unsafe.Sizeof(Value{})),
			option.Config.NeighMapEntriesGlobal,
			0,
			bpf.ConvertKeyValue,
		)
		neigh6Map = bpf.NewMap(Map6Name,
			bpf.MapTypeLRUHash,
			&Key6{},
			int(unsafe.Sizeof(Key6{})),
			&Value{},
			int(unsafe.Sizeof(Value{})),
			option.Config.NeighMapEntriesGlobal,
			0,
			bpf.ConvertKeyValue,
		)
	})
	return neigh4Map, neigh6Map
}

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

// SizeofNeighKey6 is the size of type NeighKey6.
const SizeofNeighKey6 = int(unsafe.Sizeof(Key6{}))

// Value is the MAC address for the IP-to-MAC address mappings.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Value struct {
	macaddr types.MACAddr
	pad     uint16
}

// SizeOfNeighValue is the size of type NeighValue.
const SizeOfNeighValue = int(unsafe.Sizeof(Value{}))

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Key6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format.
func (k *Key4) String() string { return k.ipv4.String() }

// String converts the key into a human readable string format.
func (k *Key6) String() string { return k.ipv6.String() }

// String converts the value into a human readable string format.
func (v *Value) String() string { return v.macaddr.String() }

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k Key4) NewValue() bpf.MapValue { return &Value{} }

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k Key6) NewValue() bpf.MapValue { return &Value{} }

// InitMaps creates the nodeport neighbors maps in the kernel.
func InitMaps(ipv4, ipv6 bool) error {
	neigh4Map, neigh6Map := neighMapsGet()
	if ipv4 {
		if err := neigh4Map.Create(); err != nil {
			return err
		}
	}
	if ipv6 {
		if err := neigh6Map.Create(); err != nil {
			return err
		}
	}
	return nil
}

// NeighRetire retires a cached neigh entry from the LRU cache
func NeighRetire(ip net.IP) {
	var neighMap *bpf.Map
	if len(ip) == net.IPv4len {
		neighMap, _ = neighMapsGet()
	} else {
		_, neighMap = neighMapsGet()
	}
	if err := neighMap.Open(); err != nil {
		return
	}
	defer neighMap.Close()
	if len(ip) == net.IPv4len {
		key := &Key4{}
		copy(key.ipv4[:], ip.To4())
		neighMap.Delete(key)
	} else {
		key := &Key6{}
		copy(key.ipv6[:], ip.To16())
		neighMap.Delete(key)
	}
}
