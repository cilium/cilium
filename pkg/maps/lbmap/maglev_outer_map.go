// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/ebpf"
)

// MaglevOuterMap represents a Maglev outer map.
type MaglevOuterMap struct {
	*ebpf.Map
}

// UpdateService sets the given inner map to be the Maglev lookup table for
// the service with the given id.
func (m *MaglevOuterMap) UpdateService(id uint16, inner *MaglevInnerMap) error {
	key := MaglevOuterKey{RevNatID: id}.toNetwork()
	val := MaglevOuterVal{FD: uint32(inner.FD())}
	return m.Map.Update(key, val, 0)
}

// MaglevOuterKey is the key of a maglev outer map.
type MaglevOuterKey struct {
	RevNatID uint16
}

// toNetwork converts a maglev outer map's key to network byte order.
// The key is in network byte order in the eBPF maps.
func (k MaglevOuterKey) toNetwork() MaglevOuterKey {
	return MaglevOuterKey{
		RevNatID: byteorder.HostToNetwork16(k.RevNatID),
	}
}

// MaglevOuterVal is the value of a maglev outer map.
type MaglevOuterVal struct {
	FD uint32
}

// NewMaglevOuterMap returns a new object representing a maglev outer map.
func NewMaglevOuterMap(name string, maxEntries int, tableSize uint32, innerMap *ebpf.MapSpec) (*MaglevOuterMap, error) {
	m := ebpf.NewMap(&ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.HashOfMaps,
		KeySize:    uint32(unsafe.Sizeof(MaglevOuterKey{})),
		ValueSize:  uint32(unsafe.Sizeof(MaglevOuterVal{})),
		MaxEntries: uint32(maxEntries),
		InnerMap:   innerMap,
		Pinning:    ebpf.PinByName,
	})

	if err := m.OpenOrCreate(); err != nil {
		return nil, err
	}

	return &MaglevOuterMap{m}, nil
}

// OpenMaglevOuterMap opens an existing pinned maglev outer map and returns an
// object representing it.
func OpenMaglevOuterMap(name string) (*MaglevOuterMap, error) {
	m, err := ebpf.LoadRegisterMap(name)
	if err != nil {
		return nil, err
	}

	return &MaglevOuterMap{m}, nil
}

// TableSize tries to determine the table size of the Maglev map.
// It does so by opening the first-available service's inner map and reading
// its size. For this to work, at least one service entry must be available.
func (m *MaglevOuterMap) TableSize() (uint32, error) {
	var firstKey MaglevOuterKey
	if err := m.NextKey(nil, &firstKey); err != nil {
		// The outer map exists but it's empty.
		return 0, fmt.Errorf("getting first key: %w", err)
	}

	var firstVal MaglevOuterVal
	if err := m.Lookup(&firstKey, &firstVal); err != nil {
		// The outer map exists but we can't read the first entry.
		return 0, fmt.Errorf("getting first value: %w", err)
	}

	inner, err := MaglevInnerMapFromID(firstVal.FD)
	if err != nil {
		// The outer map exists but we can't access the inner map
		// associated with the first entry.
		return 0, fmt.Errorf("opening first inner map: %w", err)
	}
	defer inner.Close()

	return inner.TableSize(), nil
}

// GetService gets the maglev backend lookup table for the given service id.
func (m *MaglevOuterMap) GetService(id uint16) (*MaglevInnerMap, error) {
	key := MaglevOuterKey{RevNatID: id}.toNetwork()
	var val MaglevOuterVal

	err := m.Lookup(key, &val)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, fmt.Errorf("no maglev table entry for service id %d: %w", id, err)
	}
	if err != nil {
		return nil, err
	}

	inner, err := MaglevInnerMapFromID(val.FD)
	if err != nil {
		return nil, fmt.Errorf("cannot open inner map with id %d: %w", val.FD, err)
	}

	return inner, nil
}

// DumpBackends iterates through all of the Maglev map's entries,
// opening each entry's inner map, and dumps their contents in a format
// expected by Cilium's table printer.
func (m *MaglevOuterMap) DumpBackends(ipv6 bool) (map[string][]string, error) {
	out := make(map[string][]string)

	var key MaglevOuterKey
	var val MaglevOuterVal
	which := "v4"
	if ipv6 {
		which = "v6"
	}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		inner, err := MaglevInnerMapFromID(val.FD)
		if err != nil {
			return nil, fmt.Errorf("cannot open inner map with id %d: %w", val.FD, err)
		}
		defer inner.Close()

		backends, err := inner.DumpBackends()
		if err != nil {
			return nil, fmt.Errorf("dumping inner map id %d: %w", val.FD, err)
		}

		// The service ID is read from the map in network byte order,
		// convert to host byte order before displaying to the user.
		key.RevNatID = byteorder.NetworkToHost16(key.RevNatID)

		out[fmt.Sprintf("[%d]/%s", key.RevNatID, which)] = []string{backends}
	}

	return out, nil
}
