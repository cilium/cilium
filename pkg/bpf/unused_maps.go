// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/cilium/pkg/bpf/analyze"
	"github.com/cilium/cilium/pkg/container/set"
)

// poisonedMapLoad is a special value that is used to replace map load
// instructions that reference an unused map.
const poisonedMapLoad = 0xdeadc0de

// removeUnusedMaps analyzes the given spec to detect which parts of the code
// will be unreachable given the VariableSpecs. It then removes any MapSpecs
// that are not used by any Program.
func removeUnusedMaps(spec *ebpf.CollectionSpec, keep *set.Set[string]) (*set.Set[string], error) {
	if keep == nil {
		k := set.NewSet[string]()
		keep = &k
	}

	// VariableSpec's underlying maps always need to remain part of the
	// CollectionSpec, even if the code doesn't reference them.
	for _, v := range spec.Variables {
		keep.Insert(v.MapName())
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
				keep.Insert(inner)
			}
		}
	}

	for name, prog := range spec.Programs {
		// Load Blocks computed after compilation, or compute new ones.
		bl, err := analyze.MakeBlocks(prog.Instructions)
		if err != nil {
			return nil, fmt.Errorf("computing Blocks for Program %s: %w", prog.Name, err)
		}

		// Analyze reachability given the VariableSpecs provided at load time.
		bl, err = analyze.Reachability(bl, prog.Instructions, analyze.VariableSpecs(spec.Variables))
		if err != nil {
			return nil, fmt.Errorf("reachability analysis for program %s: %w", name, err)
		}

		// Record which maps are still referenced after reachability analysis.
		for ins, live := range bl.LiveInstructions(prog.Instructions).Forward() {
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
				*ins = asm.LoadImm(ins.Dst, poisonedMapLoad, asm.DWord)
			}
		}
	}

	// Delete unused MapSpecs so ebpf-go doesn't create them when using
	// LoadCollection.
	for name := range spec.Maps {
		if !keep.Has(name) {
			delete(spec.Maps, name)
		}
	}

	return keep, nil
}

// verifyUnusedMaps makes sure that all Maps appearing in the Collection are
// actually used by at least one Program in the Collection after the verifier
// has done its dead code elimination.
//
// This validates Cilium's user space dead code elimination logic, which removes
// unused MapSpecs from the CollectionSpec before loading it into the kernel.
//
// It should only be invoked in debug mode, since it's expensive to run.
func verifyUnusedMaps(coll *ebpf.Collection, ignore *set.Set[string]) error {
	mapsByID := make(map[ebpf.MapID]string)
	unused := set.NewSet[string]()
	for name, m := range coll.Maps {
		info, err := m.Info()
		if err != nil {
			return fmt.Errorf("getting map info for %s: %w", name, err)
		}

		id, bool := info.ID()
		if !bool {
			return fmt.Errorf("no map ID for map %s", name)
		}

		mapsByID[id] = name

		// If the map is in the ignore set, always consider it used. This is for
		// maps like .rodata that are never removed from the CollectionSpec since
		// they are referenced by VariableSpecs.
		if ignore == nil || !ignore.Has(name) {
			unused.Insert(name)
		}
	}

	for name, prog := range coll.Programs {
		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("getting info for program %s: %w", name, err)
		}

		insns, err := info.Instructions()
		if err != nil {
			return fmt.Errorf("getting instructions for program %s: %w", name, err)
		}

		// Find all live maps after the verifier's dead code elimination.
		for _, ins := range insns {
			if !ins.IsLoadFromMap() {
				continue
			}

			id := ebpf.MapID(ins.Constant)
			name, found := mapsByID[id]
			if !found {
				return fmt.Errorf("program %s references map with unknown ID %d", name, id)
			}

			// Map appears in the instruction stream, so it's being used by the Program.
			unused.Remove(name)
		}
	}

	if unused.Len() > 0 {
		return fmt.Errorf("unused maps after dead code elimination: %s", unused.AsSlice())
	}

	return nil
}
