// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configmap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	// MapName name of map used to pin map for datapath
	MapName = "cilium_runtime_config"
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
	m *bpf.Map
}

// LoadMap loads the pre-initialized config map for access.
// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
// It needs to initialized beforehand via the Cilium Agent.
func LoadMap(logger *slog.Logger) (Map, error) {
	var index Index
	var value Value

	m, err := bpf.OpenMap(bpf.MapPath(logger, MapName), &index, &value)
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf map: %w", err)
	}

	return &configMap{m: m}, nil
}

func (m *configMap) Get(index Index) (uint64, error) {
	if m.m == nil {
		return 0, fmt.Errorf("config map not started")
	}

	v, err := m.m.Lookup(&index)
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
	if m.m == nil {
		return fmt.Errorf("config map not started")
	}

	value := Value(val)
	return m.m.Update(&index, &value)
}
