// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package worldcidrsmap

import (
	"net/netip"
	"unsafe"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapMaxEntries = 1 << 14
	MapName4      = "cilium_world_cidrs4"
)

// WorldCIDRKey4 is the key of a world CIDRs map.
type WorldCIDRKey4 struct {
	// PrefixLen is full 32 bits of mask bits
	PrefixLen uint32
	IP        types.IPv4
}

// WorldCIDRVal is the value of world CIDRs maps.
type WorldCIDRVal struct {
	Exists uint8
}

// wolrdCIDRsMap is the internal representation of a world CIDRs map.
type worldCIDRsMap struct {
	*ebpf.Map
}

var (
	WorldCIDRsMap *worldCIDRsMap
)

// InitWorldCIDRsMap initializes the world CIDRs map.
func InitWorldCIDRsMap() error {
	return initWorldCIDRsMap(MapName4, true)
}

// OpenWorldCIDRsMap initializes the world CIDRs map.
func OpenWorldCIDRsMap() error {
	return initWorldCIDRsMap(MapName4, false)
}

// initWorldCIDRsMap initializes the world CIDR map.
func initWorldCIDRsMap(worldCIDRsMapName string, create bool) error {
	var m *ebpf.Map

	if create {
		m = ebpf.NewMap(&ebpf.MapSpec{
			Name:       worldCIDRsMapName,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(WorldCIDRKey4{})),
			ValueSize:  uint32(unsafe.Sizeof(WorldCIDRVal{})),
			MaxEntries: uint32(MapMaxEntries),
			Pinning:    ebpf.PinByName,
		})

		if err := m.OpenOrCreate(); err != nil {
			return err
		}
	} else {
		var err error

		if m, err = ebpf.LoadRegisterMap(worldCIDRsMapName); err != nil {
			return err
		}
	}

	WorldCIDRsMap = &worldCIDRsMap{
		m,
	}

	return nil
}

func NewWorldCIDRKey4(cidr netip.Prefix) WorldCIDRKey4 {
	key := WorldCIDRKey4{}

	ones := cidr.Bits()
	key.IP = cidr.Addr().As4()
	key.PrefixLen = uint32(ones)

	return key
}

func NewWorldCIDRVal() WorldCIDRVal {
	return WorldCIDRVal{
		Exists: 1,
	}
}

// Matches returns true if the cidr parameter matches the world CIDR key.
func (k *WorldCIDRKey4) Matches(cidr netip.Prefix) bool {
	return k.GetCIDR() == cidr
}

func (k *WorldCIDRKey4) GetCIDR() netip.Prefix {
	return netip.PrefixFrom(k.IP.Addr(), int(k.PrefixLen))
}

// Add adds the givenCIDR to the map.
func (m *worldCIDRsMap) Add(cidrs ...netip.Prefix) error {
	if len(cidrs) == 0 {
		return nil
	}

	keys := make([]WorldCIDRKey4, 0, len(cidrs))
	vals := make([]WorldCIDRVal, 0, len(cidrs))

	for _, cidr := range cidrs {
		keys = append(keys, NewWorldCIDRKey4(cidr))
		vals = append(vals, NewWorldCIDRVal())
	}

	_, err := m.Map.BatchUpdate(keys, vals, nil)
	return err
}

// Delete deletes the given CIDR from the map.
func (m *worldCIDRsMap) Delete(cidrs ...netip.Prefix) error {
	if len(cidrs) == 0 {
		return nil
	}

	keys := make([]WorldCIDRKey4, 0, len(cidrs))

	for _, cidr := range cidrs {
		keys = append(keys, NewWorldCIDRKey4(cidr))
	}

	_, err := m.Map.BatchDelete(keys, nil)
	return err
}

// WorldCIDRsIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a world CIDR map.
type WorldCIDRsIterateCallback func(netip.Prefix)

// IterateWithCallback iterates through all the keys/values of a world CIDRs
// map, passing each key/value pair to the cb callback.
func (m worldCIDRsMap) IterateWithCallback(cb WorldCIDRsIterateCallback) error {
	return m.Map.IterateWithCallback(&WorldCIDRKey4{}, &WorldCIDRVal{},
		func(k, v interface{}) {
			key := k.(*WorldCIDRKey4)
			p := key.GetCIDR()
			cb(p)
		})
}
