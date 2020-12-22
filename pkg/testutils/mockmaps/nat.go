// Copyright 2020 Authors of Cilium
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
