// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package registry

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/lock"
)

var Cell = cell.Module(
	"map-registry",
	"Registry of eBPF map specifications that can be modified",
	cell.Provide(NewMapSpecRegistry),
)

//go:embed bpf_maps.o
var bpfMapsELF []byte

// MapSpecRegistry contains eBPF map specifications for all maps in the datapath that may
// be modified at runtime. This registry allows cells to modify map specifications
// during hive construction. For example changing the max entries of a map based on
// configuration parameters.
//
// Once the registry has been started, map specifications can be retrieved but not modified.
//
// The loader will replace the map specifications of eBPF collections with those from this registry.
//
// Map packages which may create maps explicitly before programs are loaded should also use this registry
// to obtain the correct map specifications.
type MapSpecRegistry struct {
	mu       lock.Mutex
	started  bool
	mapSpecs map[string]*ebpf.MapSpec
}

func NewMapSpecRegistry(lifecycle cell.Lifecycle) (*MapSpecRegistry, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfMapsELF))
	if err != nil {
		return nil, err
	}

	reg := &MapSpecRegistry{
		mapSpecs: spec.Maps,
	}

	lifecycle.Append(reg)
	return reg, nil
}

var (
	ErrRegistryAlreadyStarted = errors.New("map spec registry has already been started")
	ErrRegistryNotYetStarted  = errors.New("map spec registry has not yet been started")
	ErrMapSpecNotFound        = errors.New("map spec not found")
)

func (r *MapSpecRegistry) ModifyMapSpec(name string, modify func(*ebpf.MapSpec) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.started {
		return ErrRegistryAlreadyStarted
	}

	spec, ok := r.mapSpecs[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrMapSpecNotFound, name)
	}

	return modify(spec)
}

func (r *MapSpecRegistry) Get(name string) (*ebpf.MapSpec, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.started {
		return nil, ErrRegistryNotYetStarted
	}

	spec, ok := r.mapSpecs[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMapSpecNotFound, name)
	}

	return spec.Copy(), nil
}

func (r *MapSpecRegistry) Start(_ cell.HookContext) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.started = true

	// Make a deep copy of the map specs, to prevent anyone from modifying
	// pointers they obtained from the registry after Start() has been called.
	mapsCopy := make(map[string]*ebpf.MapSpec, len(r.mapSpecs))
	for name, spec := range r.mapSpecs {
		mapsCopy[name] = spec.Copy()
	}
	r.mapSpecs = mapsCopy
	return nil
}

func (r *MapSpecRegistry) Stop(_ cell.HookContext) error {
	return nil
}
