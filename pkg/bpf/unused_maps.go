// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// poisonedMapLoad is a special value that is used to replace map load
// instructions that reference an unused map.
const poisonedMapLoad = 0xdeadc0de

// fixedResources returns a set of map names that must not be removed from
// the CollectionSpec, regardless of whether they are referenced by any Program.
//
// All sets passed in opts are merged into the resulting set.
func fixedResources(spec *ebpf.CollectionSpec, opts ...*set.Set[string]) *set.Set[string] {
	fixed := set.NewSet[string]()

	for _, s := range opts {
		if s == nil {
			continue
		}
		fixed.Merge(*s)
	}

	// VariableSpec's underlying maps always need to remain part of the
	// CollectionSpec, even if the code doesn't reference them.
	for _, v := range spec.Variables {
		fixed.Insert(v.SectionName)
	}

	// When populating a map-in-map with contents (other maps) defined at
	// compile time, we need to ensure the inner maps are not pruned
	// since they will not be directly referenced in the code.
	for _, m := range spec.Maps {
		if m.Type != ebpf.ArrayOfMaps && m.Type != ebpf.HashOfMaps {
			continue
		}

		for _, c := range m.Contents {
			if inner, ok := c.Value.(string); ok {
				fixed.Insert(inner)
			}
		}
	}

	return &fixed
}

// removeUnusedMaps analyzes the given spec to detect which parts of the code
// will be unreachable given the VariableSpecs. It then removes any MapSpecs
// that are not used by any Program.
func removeUnusedMaps(spec *ebpf.CollectionSpec, fixed *set.Set[string], reach reachables, logger *slog.Logger) error {
	if reach == nil {
		return fmt.Errorf("reachability information is required")
	}

	// Take care not to modify the caller's set.
	keep := set.NewSet[string]()
	if fixed != nil {
		keep = fixed.Clone()
	}

	for name := range spec.Programs {
		r, ok := reach[name]
		if !ok {
			return fmt.Errorf("missing reachability information for program %s", name)
		}

		// Record which maps are still referenced after reachability analysis.
		for iter, live := range r.Iterate() {
			ins := iter.Instruction()
			if !ins.IsLoadFromMap() {
				continue
			}

			if live {
				// Mark the map as used, so it won't be pruned from the CollectionSpec.
				keep.Insert(ins.Reference())
			} else {
				// Remove all map references from unreachable instructions. Replace the map
				// pointer load instruction with a new instruction with a recognizable
				// poison value, without a metadata reference to the MapSpec. This will
				// prevent LoadAndAssign from pulling in the map unconditionally during
				// lazy-loading.
				//
				// If, for whatever reason, we caused a false positive and the program
				// attempts to use this value as map pointer, it should be clear from
				// the verifier log.
				comm := asm.Comment(fmt.Sprintf("%s (bug: poisoned map load in live block)", ins.Source()))
				*ins = asm.LoadImm(ins.Dst, poisonedMapLoad, asm.DWord).WithSource(comm)
			}
		}
	}

	// Delete unused MapSpecs so ebpf-go doesn't create them when using
	// LoadCollection.
	var deleted []string
	for name := range spec.Maps {
		if !keep.Has(name) {
			delete(spec.Maps, name)
			deleted = append(deleted, name)
		}
	}
	if logger != nil && len(deleted) > 0 {
		logger.Debug("Removed unused maps from CollectionSpec", logfields.Maps, deleted)
	}

	return nil
}

// freedMaps finds maps that have been freed by the kernel after the verifier's
// dead code elimination concluded that they are unused.
//
// Maps appearing in fixed are considered used and will never be reported as
// freed.
//
// It should only be invoked in debug mode, since it's expensive to run.
func freedMaps(coll *ebpf.Collection, fixed *set.Set[string]) ([]string, error) {
	mapsByID := make(map[ebpf.MapID]string)
	unused := set.NewSet[string]()

	for name, m := range coll.Maps {
		info, err := m.Info()
		if err != nil {
			return nil, fmt.Errorf("getting map info for %s: %w", name, err)
		}

		id, bool := info.ID()
		if !bool {
			return nil, fmt.Errorf("no map ID for map %s", name)
		}

		mapsByID[id] = name

		// If a map is in the fixed set, always consider it used since user space
		// explicitly requested it to be created, e.g. as a LoadAndAssign object or
		// .rodata.
		if fixed == nil || !fixed.Has(name) {
			unused.Insert(name)
		}
	}

	for name, prog := range coll.Programs {
		info, err := prog.Info()
		if err != nil {
			return nil, fmt.Errorf("getting info for program %s: %w", name, err)
		}

		insns, err := info.Instructions()
		if err != nil {
			return nil, fmt.Errorf("getting instructions for program %s: %w", name, err)
		}

		for _, ins := range insns {
			if !ins.IsLoadFromMap() {
				continue
			}

			id := ebpf.MapID(ins.Constant)
			name, found := mapsByID[id]
			if !found {
				return nil, fmt.Errorf("program %s references map with unknown ID %d", name, id)
			}

			unused.Remove(name)
		}
	}

	return unused.AsSlice(), nil
}
