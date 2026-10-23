// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
)

type fakeMapEntry struct {
	key   bpf.MapKey
	value bpf.MapValue
}

// fakeBPFMap provides isolated shared policy maps for unit tests.
type fakeBPFMap struct {
	lock    lock.RWMutex
	entries map[string]fakeMapEntry
	dumpErr error
	// maxEntries, if non-zero, makes adding new entries fail with ENOSPC once the map
	// has this many entries, like a full BPF map. Existing entries can still be updated.
	maxEntries int
}

// newFakeBPFMap creates a new in-memory fakeBPFMap.
func newFakeBPFMap() *fakeBPFMap {
	return &fakeBPFMap{
		entries: make(map[string]fakeMapEntry),
	}
}

func (m *fakeBPFMap) Update(key bpf.MapKey, value bpf.MapValue) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	if _, exists := m.entries[key.String()]; !exists && m.maxEntries > 0 && len(m.entries) >= m.maxEntries {
		return fmt.Errorf("update: %w", unix.ENOSPC)
	}
	m.entries[key.String()] = fakeMapEntry{key: key, value: value}
	return nil
}

func (m *fakeBPFMap) Delete(key bpf.MapKey) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.entries, key.String())
	return nil
}

func (m *fakeBPFMap) Lookup(key bpf.MapKey) (any, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	entry, ok := m.entries[key.String()]
	if !ok {
		return nil, ebpf.ErrKeyNotExist
	}
	return entry.value, nil
}

func (m *fakeBPFMap) DumpWithCallback(cb bpf.DumpCallback) error {
	if m.dumpErr != nil {
		return m.dumpErr
	}
	if cb == nil {
		return nil
	}
	m.lock.RLock()
	entries := make([]fakeMapEntry, 0, len(m.entries))
	for _, entry := range m.entries {
		entries = append(entries, entry)
	}
	m.lock.RUnlock()

	for _, entry := range entries {
		cb(entry.key, entry.value)
	}
	return nil
}
