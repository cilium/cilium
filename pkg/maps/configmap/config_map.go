// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configmap

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
)

const (
	// MapName name of map used to pin map for datapath
	MapName = "cilium_runtime_config"

	// MaxEntries represents the maximum number of config entries.
	// Initially defined as 256, so that downgrade from a future version having more than one
	// entry works without necessarily resizing the map. Entries not known by the datapath
	// version are simply ignored.
	MaxEntries = 256
)

// Index is the index to the runtime config array.
type Index uint32

// All supported indices in one place.
// Must be in sync with RUNTIME_CONFIG_ enum in bpf/lib/common.h
const (
	UTimeOffset Index = iota
	AgentLiveness
)

// String pretty print the Index
func (r Index) String() string {
	switch r {
	case UTimeOffset:
		return "UTimeOffset"
	case AgentLiveness:
		return "AgentLiveness"
	default:
		return "Unknown"
	}
}

// Value is the generic datapath runtime config value.
type Value uint64

func (k *Index) New() bpf.MapKey { return new(Index) }

// String pretty print the config Value.
func (v *Value) String() string {
	return fmt.Sprintf("%d", uint64(*v))
}

func (v *Value) New() bpf.MapValue { return new(Value) }

// Map provides access to the eBPF map configmap.
type Map interface {
	// Update writes the given uint64 value to the bpf map at the given index.
	Update(index Index, val uint64) error

	Get(index Index) (uint64, error)
}

type configMap struct {
	bpfMap *bpf.Map
}

func newConfigMap() *configMap {
	var index Index
	var value Value

	return &configMap{
		bpfMap: bpf.NewMap(MapName,
			ebpf.Array,
			&index,
			&value,
			MaxEntries,
			0,
		),
	}
}

// LoadMap loads the pre-initialized config map for access.
// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
// It needs to initialized beforehand via the Cilium Agent.
func LoadMap() (Map, error) {
	var index Index
	var value Value

	m, err := bpf.OpenMap(bpf.MapPath(MapName), &index, &value)
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf map: %w", err)
	}

	return &configMap{bpfMap: m}, nil
}

func (m *configMap) init() error {
	if err := m.bpfMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *configMap) close() error {
	if err := m.bpfMap.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}

func (m *configMap) Get(index Index) (uint64, error) {
	v, err := m.bpfMap.Lookup(&index)
	if err != nil {
		return 0, fmt.Errorf("failed to lookup entry: %w", err)
	}

	mapValue, ok := v.(*Value)
	if !ok {
		return 0, fmt.Errorf("wrong config map value: %w", err)
	}

	return uint64(*mapValue), nil
}

func (m *configMap) Update(index Index, val uint64) error {
	value := Value(val)
	return m.bpfMap.Update(&index, &value)
}
