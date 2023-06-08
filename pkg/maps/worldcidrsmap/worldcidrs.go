// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package worldcidrsmap

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapMaxEntries = 1 << 14
	MapName4      = "cilium_world_cidrs4"
)

type Map interface {
	// Load initializes the map. If create is true, will create the map
	// if missing. Otherwise, will return error if the map does not exist
	Load(create bool) error

	IterateWithCallback(cb WorldCIDRsIterateCallback) error

	Add(cidrs ...netip.Prefix) error
	Delete(cidrs ...netip.Prefix) error
}

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
	v4map *ebpf.Map
}

// newWorldCIDRsMap initializes the world CIDR map.
func newWorldCIDRsMap() *worldCIDRsMap {
	return &worldCIDRsMap{}
}

// LoadWorldCIDRsMap loads, but does not create, the world cidrs map for access
// This is used for the CLI
func LoadWorldCIDRsMap() (Map, error) {
	m := newWorldCIDRsMap()

	if err := m.Load(false); err != nil {
		return nil, err
	}

	return m, nil
}

// Load creates
func (m *worldCIDRsMap) Load(create bool) error {
	if m.v4map != nil {
		return nil
	}

	if create {
		m.v4map = ebpf.NewMap(&ebpf.MapSpec{
			Name:       MapName4,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(WorldCIDRKey4{})),
			ValueSize:  uint32(unsafe.Sizeof(WorldCIDRVal{})),
			MaxEntries: uint32(MapMaxEntries),
			Pinning:    ebpf.PinByName,
		})

		if err := m.v4map.OpenOrCreate(); err != nil {
			m.v4map = nil
			return fmt.Errorf("failed to open or create bpf map %s: %w", MapName4, err)
		}
	} else {
		var err error

		m.v4map, err = ebpf.LoadRegisterMap(MapName4)
		if err != nil {
			return fmt.Errorf("failed to open bpf map %s: %w", MapName4, err)
		}
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
		// TODO: ipv6 support
		if cidr.Addr().Is6() {
			continue
		}
		keys = append(keys, NewWorldCIDRKey4(cidr))
		vals = append(vals, NewWorldCIDRVal())
	}

	_, err := m.v4map.BatchUpdate(keys, vals, nil)
	return err
}

// Delete deletes the given CIDR from the map.
func (m *worldCIDRsMap) Delete(cidrs ...netip.Prefix) error {
	if len(cidrs) == 0 {
		return nil
	}

	keys := make([]WorldCIDRKey4, 0, len(cidrs))

	for _, cidr := range cidrs {
		// TODO: ipv6 support
		if cidr.Addr().Is6() {
			continue
		}
		keys = append(keys, NewWorldCIDRKey4(cidr))
	}

	_, err := m.v4map.BatchDelete(keys, nil)
	return err
}

// WorldCIDRsIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a world CIDR map.
type WorldCIDRsIterateCallback func(netip.Prefix)

// IterateWithCallback iterates through all the keys/values of a world CIDRs
// map, passing each key/value pair to the cb callback.
func (m worldCIDRsMap) IterateWithCallback(cb WorldCIDRsIterateCallback) error {
	err := m.v4map.IterateWithCallback(&WorldCIDRKey4{}, &WorldCIDRVal{},
		func(k, v interface{}) {
			key := k.(*WorldCIDRKey4)
			p := key.GetCIDR()
			cb(p)
		})

	if err != nil {
		return fmt.Errorf("failed to list map %s: %w", MapName4, err)
	}
	return nil
}
