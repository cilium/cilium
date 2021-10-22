// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package lbmap

import (
	"unsafe"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// maglevInnerMap is the internal representation of a maglev inner map.
type maglevInnerMap struct {
	*ebpf.Map
	tableSize uint32
}

// MaglevInnerKey is the key of a maglev inner map.
type MaglevInnerKey struct {
	Zero uint32
}

// MaglevInnerVal is the value of a maglev inner map.
type MaglevInnerVal struct {
	BackendIDs []loadbalancer.BackendID
}

// newMaglevInnerMapSpec returns the spec for a maglev inner map.
func newMaglevInnerMapSpec(tableSize uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       "cilium_maglev_inner",
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(MaglevInnerKey{})),
		ValueSize:  uint32(unsafe.Sizeof(uint32(0)) * uintptr(tableSize)),
		MaxEntries: 1,
	}
}

// newMaglevInnerMap returns a new object representing a maglev inner map.
func newMaglevInnerMap(tableSize uint32) (*maglevInnerMap, error) {
	spec := newMaglevInnerMapSpec(tableSize)

	m := ebpf.NewMap(spec)
	if err := m.OpenOrCreate(); err != nil {
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
	value := &MaglevInnerVal{
		BackendIDs: make([]loadbalancer.BackendID, m.tableSize),
	}

	if err := m.Map.Lookup(key, &value.BackendIDs); err != nil {
		return nil, err
	}

	return value, nil
}

// Update updates the value associated with a given key for a maglev inner map.
func (m *maglevInnerMap) Update(key *MaglevInnerKey, value *MaglevInnerVal) error {
	return m.Map.Update(key, &value.BackendIDs, 0)
}
