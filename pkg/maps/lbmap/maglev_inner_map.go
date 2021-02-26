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
	"errors"
	"unsafe"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maglev"

	"golang.org/x/sys/unix"
)

// maglevInnerMap is the internal representation of a maglev inner map.
type maglevInnerMap struct {
	*ebpf.Map
	tableSize uint32
}

// MaglevInnerKey is the key of a maglev inner map.
type MaglevInnerKey struct {
	Slot uint32
}

type maglevInnerKeys []*MaglevInnerKey

func (m maglevInnerKeys) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	const size = int(unsafe.Sizeof(MaglevInnerKey{}))
	buf := make([]byte, 0, len(m)*size)
	for i := range m {
		b := make([]byte, size)
		byteorder.Native.PutUint32(b, m[i].Slot)
		buf = append(buf, b...)
	}
	return buf, nil
}

// MaglevInnerVal is the value of a maglev inner map.
type MaglevInnerVal struct {
	BackendIDs [MaglevInnerElems]uint16
}

type maglevInnerVals []*MaglevInnerVal

func (m maglevInnerVals) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	const size = int(unsafe.Sizeof(MaglevInnerVal{}))
	buf := make([]byte, 0, len(m)*size)
	for i := range m {
		for j, v := range m[i].BackendIDs {
			b := make([]byte, unsafe.Sizeof(v))
			byteorder.Native.PutUint16(b, m[i].BackendIDs[j])
			buf = append(buf, b...)
		}
	}
	return buf, nil
}

// newMaglevInnerMapSpec returns the spec for a maglev inner map.
func newMaglevInnerMapSpec(name string, tableSize uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(MaglevInnerKey{})),
		ValueSize:  uint32(unsafe.Sizeof(MaglevInnerVal{})),
		MaxEntries: TableSizeToMaxEntries(tableSize),
		Flags:      unix.BPF_F_INNER_MAP,
	}
}

// newMaglevInnerMap returns a new object representing a maglev inner map.
func newMaglevInnerMap(name string, tableSize uint32) (*maglevInnerMap, error) {
	spec := newMaglevInnerMapSpec(name, tableSize)

	m := ebpf.NewMap(spec)
	if err := m.OpenOrCreate(); err != nil && errors.Is(err, ebpf.ErrNotSupported) {
		log.WithError(err).Fatal("Maglev mode requires kernel 5.10 or newer")
	} else if err != nil {
		return nil, err
	}

	return &maglevInnerMap{
		Map:       m,
		tableSize: tableSize,
	}, nil
}

// MaglevInnerMapFromID returns a new object representing the maglev inner map
// identified by an ID.
func MaglevInnerMapFromID(id int, tableSize uint32) (*maglevInnerMap, error) {
	m, err := ebpf.MapFromID(id)
	if err != nil {
		return nil, err
	}

	return &maglevInnerMap{
		Map:       m,
		tableSize: tableSize,
	}, nil
}

// Lookup returns the value associated with a given key for a maglev inner map.
func (m *maglevInnerMap) Lookup(key *MaglevInnerKey) (*MaglevInnerVal, error) {
	value := &MaglevInnerVal{}

	if err := m.Map.Lookup(key, &value.BackendIDs); err != nil {
		return nil, err
	}

	return value, nil
}

// Update updates the value associated with a given key for a maglev inner map.
func (m *maglevInnerMap) Update(key *MaglevInnerKey, value *MaglevInnerVal) error {
	return m.Map.Update(key, &value.BackendIDs, 0)
}

// TableSizeToMaxEntries returns the max entries of the Maglev inner map
// depending on the table size (M).
func TableSizeToMaxEntries(size uint32) uint32 {
	return (size / MaglevInnerElems) + 1
}

// maxEntriesToTableSize stores the inverse calculation from the above
// function. The reason this is populated ahead of time in init() and stored is
// because the calculation is lossy (due to the integer division on a prime
// number).
var maxEntriesToTableSize map[uint32]uint32

func init() {
	maxEntriesToTableSize = make(map[uint32]uint32, len(maglev.SupportedPrimes))

	for _, v := range maglev.SupportedPrimes {
		u := uint32(v)
		maxEntriesToTableSize[TableSizeToMaxEntries(u)] = u
	}
}
