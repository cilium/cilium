// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/cilium/pkg/bpf/analyze"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// removeUnusedTailcalls removes tail calls that are not reachable from
// entrypoint programs.
func removeUnusedTailcalls(logger *slog.Logger, spec *ebpf.CollectionSpec) error {
	// Build a map of tail call slots to ProgramSpecs.
	tails := make(map[uint32]*ebpf.ProgramSpec)
	for _, prog := range spec.Programs {
		if !isTailCall(prog) {
			continue
		}

		slot, err := tailCallSlot(prog)
		if err != nil {
			return fmt.Errorf("getting tail call slot: %w", err)
		}

		tails[slot] = prog
	}

	// Discover all tail calls reachable from entry points.
	visited := set.Set[*ebpf.ProgramSpec]{}
	for _, prog := range spec.Programs {
		if !isEntrypoint(prog) {
			continue
		}

		if err := visitProgram(logger, prog, spec.Variables, tails, &visited); err != nil {
			return err
		}
	}

	// Remove unreferenced tail calls from the CollectionSpec.
	for name, prog := range spec.Programs {
		if !isTailCall(prog) {
			continue
		}

		if visited.Has(prog) {
			continue
		}

		delete(spec.Programs, name)

		logger.Debug("Deleted unreferenced tail call from CollectionSpec", logfields.Prog, prog.Name)
	}

	return nil
}

func visitProgram(logger *slog.Logger, prog *ebpf.ProgramSpec, vars map[string]*ebpf.VariableSpec, tails map[uint32]*ebpf.ProgramSpec, visited *set.Set[*ebpf.ProgramSpec]) error {
	if visited.Has(prog) {
		return nil
	}
	visited.Insert(prog)

	// Load Blocks computed after compilation, or compute new ones.
	bl, err := analyze.MakeBlocks(prog.Instructions)
	if err != nil {
		return fmt.Errorf("computing Blocks for Program %s: %w", prog.Name, err)
	}

	// Analyze reachability given the VariableSpecs provided at load time.
	r, err := analyze.Reachability(bl, prog.Instructions, analyze.VariableSpecs(vars))
	if err != nil {
		return fmt.Errorf("reachability analysis for program %s: %w", prog.Name, err)
	}

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
		iter = iter.Clone()

		// The preceding instruction must be the load of the index into R3.
		if !iter.Previous() {
			continue
		}
		movIdx := iter.Instruction()
		if movIdx.OpCode.ALUOp() != asm.Mov || movIdx.Dst != asm.R3 {
			continue
		}
		slot := uint32(movIdx.Constant)

		// The preceding instruction must be the load of the calls pointer map into R2.
		if !iter.Previous() {
			continue
		}
		mapPtr := iter.Instruction()
		if !mapPtr.IsLoadFromMap() {
			continue
		}
		ref := mapPtr.Reference()

		// Only consider calls into cilium_calls. Some programs statically call into
		// the policy map, only if the slot (endpoint id) is known at compile time.
		if ref != callsMap {
			logger.Debug("Ignoring tail call into map",
				logfields.Reference, ref,
				logfields.Prog, prog.Name,
			)
			continue
		}

		if tail := tails[slot]; tail != nil {
			if err := visitProgram(logger, tail, vars, tails, visited); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("missed tail call in program %s to slot %d at insn %d", prog.Name, slot, iter.Index())
		}
	}

	return nil
}
