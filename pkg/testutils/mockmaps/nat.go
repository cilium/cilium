// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mockmaps

import (
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/nat"
)

// NatMockMap implements the NatMap interface and can be used for unit tests.
type NatMockMap struct {
	Entries []nat.NatMapRecord
}

// NewNatMockMap is a constructor for a NatMockMap.
func NewNatMockMap(records []nat.NatMapRecord) *NatMockMap {
	m := &NatMockMap{}
	m.Entries = records
	return m
}

// Open does nothing, mock maps need not be opened.
func (m *NatMockMap) Open() error {
	return nil
}

// Close does nothing, mock maps need not be closed either.
func (m *NatMockMap) Close() error {
	return nil
}

// Path returns a mock path for the mock map.
func (m *NatMockMap) Path() (string, error) {
	return "/this/is/a/mock/map", nil
}

// DumpEntries iterates through Map m and writes the values of the ct entries
// in m to a string.
func (m *NatMockMap) DumpEntries() (string, error) {
	return nat.DoDumpEntries(m)
}

// DumpWithCallback runs the callback on each entry of the mock map.
func (m *NatMockMap) DumpWithCallback(cb bpf.DumpCallback) error {
	if cb == nil {
		return nil
	}
	for _, e := range m.Entries {
		cb(e.Key, e.Value)
	}
	return nil
}
