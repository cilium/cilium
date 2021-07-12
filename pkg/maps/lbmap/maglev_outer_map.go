// Copyright 2021 Authors of Cilium
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

package lbmap

import (
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/ebpf"
)

const (
	// UnknownMaglevTableSize is a constant that represents an unknown table
	// size for a maglev outer map.
	UnknownMaglevTableSize = 0
)

// maglevOuterMap is the internal representation of a maglev outer map.
type maglevOuterMap struct {
	*ebpf.Map
	tableSize uint32
}

// MaglevOuterKey is the key of a maglev outer map.
type MaglevOuterKey struct {
	RevNatID uint16
}

// MaglevOuterVal is the value of a maglev outer map.
type MaglevOuterVal struct {
	FD uint32
}

// NewMaglevOuterMap returns a new object representing a maglev outer map.
func NewMaglevOuterMap(name string, maxEntries int, tableSize uint32, innerMap *ebpf.MapSpec) (*maglevOuterMap, error) {
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

	return &maglevOuterMap{
		Map:       m,
		tableSize: tableSize,
	}, nil
}

// OpenMaglevOuterMap opens an existing pinned maglev outer map and returns an
// object representing it.
func OpenMaglevOuterMap(name string, tableSize uint32) (*maglevOuterMap, error) {
	m, err := ebpf.OpenMap(name)
	if err != nil {
		return nil, err
	}

	return &maglevOuterMap{
		Map:       m,
		tableSize: tableSize,
	}, nil
}

// MaglevOuterMapTableSize tries to determine the table size of a given maglev
// outer map.
//
// The function returns:
// - a bool indicating whether the outer map exists or not
// - an integer indicating the table size. In case the table size cannot be
//   determined, the UnknownMaglevTableSize constant (0) is returned.
func MaglevOuterMapTableSize(mapName string) (bool, uint32) {
	prevMap, err := ebpf.LoadPinnedMap(bpf.MapPath(mapName), nil)
	if err != nil {
		// No outer map found.
		return false, UnknownMaglevTableSize
	}
	defer prevMap.Close()

	var firstKey MaglevOuterKey
	if err = prevMap.NextKey(nil, &firstKey); err != nil {
		// The outer map exists but it's empty.
		return true, UnknownMaglevTableSize
	}

	var firstVal MaglevOuterVal
	if err = prevMap.Lookup(&firstKey, &firstVal); err != nil {
		// The outer map exists but we can't read the first entry.
		return true, UnknownMaglevTableSize
	}

	innerMap, err := ebpf.MapFromID(int(firstVal.FD))
	if err != nil {
		// The outer map exists but we can't access the inner map
		// associated with the first entry.
		return true, UnknownMaglevTableSize
	}
	defer innerMap.Close()

	return true, innerMap.ValueSize() / uint32(unsafe.Sizeof(uint16(0)))
}

// Update updates the value associated with a given key for a maglev outer map.
func (m *maglevOuterMap) Update(key *MaglevOuterKey, value *MaglevOuterVal) error {
	return m.Map.Update(key, value, 0)
}

// MaglevOuterIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a metrics map.
type MaglevOuterIterateCallback func(*MaglevOuterKey, *MaglevOuterVal)

// IterateWithCallback iterates through all the keys/values of a metrics map,
// passing each key/value pair to the cb callback
func (m maglevOuterMap) IterateWithCallback(cb MaglevOuterIterateCallback) error {
	return m.Map.IterateWithCallback(&MaglevOuterKey{}, &MaglevOuterVal{}, func(k, v interface{}) {
		key := k.(*MaglevOuterKey)
		value := v.(*MaglevOuterVal)

		cb(key, value)
	})
}

// ToNetwork converts a maglev outer map's key to network byte order.
func (k *MaglevOuterKey) ToNetwork() *MaglevOuterKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNatID = byteorder.HostToNetwork16(n.RevNatID)
	return &n
}
