// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/cilium/pkg/bpf/analyze"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// removeUnusedTailcalls removes tail calls that are not reachable from
// entrypoint programs.
func removeUnusedTailcalls(logger *slog.Logger, spec *ebpf.CollectionSpec) error {
	type tail struct {
		referenced bool
		visited    bool
		spec       *ebpf.ProgramSpec
	}

	// Build a map of entrypoint programs annotated with __section_entry.
	entrypoints := make(map[string]*ebpf.ProgramSpec)
	for _, prog := range spec.Programs {
		if isEntrypoint(prog) {
			entrypoints[prog.Name] = prog
		}
	}

	// Build a map of tail call slots to ProgramSpecs.
	tailcalls := make(map[uint32]*tail)
	for _, prog := range spec.Programs {
		if !isTailCall(prog) {
			continue
		}

		slot, err := tailCallSlot(prog)
		if err != nil {
			return fmt.Errorf("getting tail call slot: %w", err)
		}

		tailcalls[slot] = &tail{
			spec: prog,
		}
	}

	// Discover all tailcalls that are reachable from the given program.
	visit := func(prog *ebpf.ProgramSpec, tailcalls map[uint32]*tail) error {
		// Load Blocks computed after compilation, or compute new ones.
		bl, err := analyze.MakeBlocks(prog.Instructions)
		if err != nil {
			return fmt.Errorf("computing Blocks for Program %s: %w", prog.Name, err)
		}

		// Analyze reachability given the VariableSpecs provided at load time.
		bl, err = analyze.Reachability(bl, prog.Instructions, analyze.VariableSpecs(spec.Variables))
		if err != nil {
			return fmt.Errorf("reachability analysis for program %s: %w", prog.Name, err)
		}

		var window []*asm.Instruction
		const windowSize = 3

		i := -1
		for ins, live := range bl.LiveInstructions(prog.Instructions) {
			i++
			if !live {
				continue
			}

			// create a sliding window of live instructions
			window = append(window, ins)
			if len(window) < windowSize {
				continue
			}
			if len(window) > windowSize {
				copy(window, window[1:])
				window = window[:windowSize]
			}

			// The `tail_call_static` C function is always used to call tail calls when
			// the map index is known at compile time.
			// Due to inline ASM this generates the following instructions:
			//   Mov R1, Rx
			//   Mov R2, <map>
			//   Mov R3, <index>
			//   call tail_call

			// Find the tail call instruction.
			inst := window[windowSize-1]
			if !inst.IsBuiltinCall() || inst.Constant != int64(asm.FnTailCall) {
				continue
			}

			// Check that the previous instruction is a mov of the tail call index.
			movIdx := window[windowSize-2]
			if movIdx.OpCode.ALUOp() != asm.Mov || movIdx.Dst != asm.R3 {
				continue
			}

			// Check that the instruction before that is the load of the tail call map.
			movR2 := window[windowSize-3]
			if movR2.OpCode != asm.LoadImmOp(asm.DWord) || movR2.Src != asm.PseudoMapFD {
				continue
			}

			ref := movR2.Reference()

			// Ignore static tail calls made to maps that are not the calls map
			if ref != callsMap {
				logger.Debug(
					"skipping tail call into map other than the calls map",
					logfields.Section, prog.SectionName,
					logfields.Prog, prog.Name,
					logfields.Instruction, i,
					logfields.Reference, ref,
				)
				continue
			}

			tc := tailcalls[uint32(movIdx.Constant)]
			if tc == nil {
				return fmt.Errorf(
					"potential missed tail call in program %s to slot %d at insn %d",
					prog.Name,
					movIdx.Constant,
					i,
				)
			}

			tc.referenced = true
		}

		return nil
	}

	// Discover all tailcalls that are reachable from the entrypoints.
	for _, prog := range entrypoints {
		if err := visit(prog, tailcalls); err != nil {
			return err
		}
	}

	// Keep visiting tailcalls until no more are discovered.
reset:
	for _, tailcall := range tailcalls {
		// If a tailcall is referenced by an entrypoint or another tailcall we should visit it
		if tailcall.referenced && !tailcall.visited {
			if err := visit(tailcall.spec, tailcalls); err != nil {
				return err
			}
			tailcall.visited = true

			// Visiting this tail call might have caused tail calls earlier in the list to become referenced, but this
			// loop already skipped them. So reset the loop. If we already visited a tailcall we will ignore them anyway.
			goto reset
		}
	}

	// Remove all tailcalls that are not referenced.
	for _, tailcall := range tailcalls {
		if !tailcall.referenced {
			logger.Debug(
				"unreferenced tail call, deleting",
				logfields.Section, tailcall.spec.SectionName,
				logfields.Prog, tailcall.spec.Name,
			)

			delete(spec.Programs, tailcall.spec.Name)
		}
	}

	return nil
}
