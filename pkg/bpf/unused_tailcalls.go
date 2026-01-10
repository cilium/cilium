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

// removeUnusedTailcalls removes tail calls that are not reachable from
// entrypoint programs.
func removeUnusedTailcalls(spec *ebpf.CollectionSpec, reach reachables, logger *slog.Logger) error {
	if reach == nil {
		return fmt.Errorf("reachability information is required")
	}

	tails, err := tailCallSlots(reach)
	if err != nil {
		return fmt.Errorf("getting tail call slots: %w", err)
	}

	live, err := livePrograms(reach, tails, logger)
	if err != nil {
		return fmt.Errorf("getting live programs: %w", err)
	}

	deleteUnused(spec, live, logger)

	return nil
}

// tailCallSlots returns a map of tail call slot indices to reachableSpecs.
// Used for stepping into a ProgramSpec when its tail call slot appears in the
// instruction stream of a calling program.
func tailCallSlots(reach reachables) (map[uint32]*reachableSpec, error) {
	// Build a map of tail call slots to reachableSpecs.
	tails := make(map[uint32]*reachableSpec)
	for _, r := range reach {
		if !isTailCall(r.ProgramSpec) {
			continue
		}

		slot, err := tailCallSlot(r.ProgramSpec)
		if err != nil {
			return nil, err
		}

		tails[slot] = r
	}

	return tails, nil
}

// livePrograms returns all programs reachable from entrypoints via tail calls.
func livePrograms(reach reachables, tails map[uint32]*reachableSpec, logger *slog.Logger) (*set.Set[*ebpf.ProgramSpec], error) {
	visited := &set.Set[*ebpf.ProgramSpec]{}
	for _, r := range reach {
		if !isEntrypoint(r.ProgramSpec) {
			continue
		}

		if err := visitProgram(r, tails, visited, logger); err != nil {
			return nil, err
		}
	}

	return visited, nil
}

func visitProgram(r *reachableSpec, tails map[uint32]*reachableSpec, visited *set.Set[*ebpf.ProgramSpec], logger *slog.Logger) error {
	if visited.Has(r.ProgramSpec) {
		return nil
	}
	visited.Insert(r.ProgramSpec)

	for iter, live := range r.Iterate() {
		if !live {
			continue
		}

		// The `tail_call_static` C function is always used to call tail calls when
		// the map index is known at compile time, as opposed to `tail_call_dynamic`
		// which is used when the slot is variable, such as when jumping to a policy
		// program of an endpoint id that is resolved at runtime. Only the _static
		// macro will generate the exact instruction sequence we're looking for.
		//
		// Due to inline ASM this generates the following instructions:
		//   Mov R1, Rx
		//   Mov R2, <map>
		//   Mov R3, <index>
		//   call bpf_tail_call

		// Find a tail call instruction.
		call := iter.Instruction()
		if !call.IsBuiltinCall() || call.Constant != int64(asm.FnTailCall) {
			continue
		}

		// Start a backtracking session starting at the current instruction.
		bt := iter.Backtrack()

		// The preceding instruction must be the load of the index into R3.
		if !bt.Previous() {
			continue
		}
		movIdx := bt.Instruction()
		if movIdx.OpCode.ALUOp() != asm.Mov || movIdx.Dst != asm.R3 {
			continue
		}
		slot := uint32(movIdx.Constant)

		// The preceding instruction must be the load of the calls pointer map into R2.
		if !bt.Previous() {
			continue
		}
		mapPtr := bt.Instruction()
		if !mapPtr.IsLoadFromMap() {
			continue
		}
		ref := mapPtr.Reference()

		// Only consider calls into cilium_calls. Some programs statically call into
		// the policy map, only if the slot (endpoint id) is known at compile time.
		if ref != callsMap {
			logger.Debug("Ignoring tail call into map",
				logfields.Reference, ref,
				logfields.Prog, r.ProgramSpec.Name,
			)
			continue
		}

		if tail := tails[slot]; tail != nil {
			if err := visitProgram(tail, tails, visited, logger); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("missed tail call in program %s to slot %d at insn %d", r.ProgramSpec.Name, slot, iter.Index())
		}
	}

	return nil
}

// deleteUnused removes unreferenced tail calls from the CollectionSpec.
func deleteUnused(spec *ebpf.CollectionSpec, live *set.Set[*ebpf.ProgramSpec], logger *slog.Logger) {
	var deleted []string
	for name, prog := range spec.Programs {
		if !isTailCall(prog) {
			continue
		}

		if live.Has(prog) {
			continue
		}

		delete(spec.Programs, name)
		deleted = append(deleted, name)
	}

	if logger != nil && len(deleted) > 0 {
		logger.Debug("Removed unused tail calls from CollectionSpec", logfields.Programs, deleted)
	}
}
