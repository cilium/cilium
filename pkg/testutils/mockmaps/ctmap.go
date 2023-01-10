// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mockmaps

import (
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

// CtMockMap implements the CtMap interface and can be used for unit tests.
type CtMockMap struct {
	Entries []ctmap.CtMapRecord
}

// NewCtMockMap is a constructor for a CtMockMap.
func NewCtMockMap(records []ctmap.CtMapRecord) *CtMockMap {
	m := &CtMockMap{}
	m.Entries = records
	return m
}

// Open does nothing, mock maps need not be opened.
func (m *CtMockMap) Open() error {
	return nil
}

// Close does nothing, mock maps need not be closed either.
func (m *CtMockMap) Close() error {
	return nil
}

// Path returns a mock path for the mock map.
func (m *CtMockMap) Path() (string, error) {
	return "/this/is/a/mock/map", nil
}

// DumpEntries iterates through Map m and writes the values of the ct entries
// in m to a string.
func (m *CtMockMap) DumpEntries() (string, error) {
	return ctmap.DoDumpEntries(m)
}

// DumpWithCallback runs the callback on each entry of the mock map.
func (m *CtMockMap) DumpWithCallback(cb bpf.DumpCallback) error {
	if cb == nil {
		return nil
	}
	for _, e := range m.Entries {
		cb(e.Key, &e.Value)
	}
	return nil
}
