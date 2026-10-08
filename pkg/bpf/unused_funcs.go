// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// nop returns a no-op replacement for ins, preserving its raw width so
// instruction offsets remain identical across ELF and verified programs
// for easier debugging. Preserves the Instruction's metadata.
func nop(ins *asm.Instruction) asm.Instruction {
	if ins.OpCode.IsDWordLoad() {
		return asm.LoadImm(asm.R0, 0, asm.DWord)
	}
	return asm.Mov.Imm(asm.R0, 0)
}

// nopUnusedFuncs replaces the bodies of functions without live callers with
// nop sleds terminated by an exit.
func nopUnusedFuncs(spec *ebpf.CollectionSpec, reach reachables, logger *slog.Logger) error {
	for name, p := range spec.Programs {
		r, ok := reach[name]
		if !ok {
			return fmt.Errorf("missing reachability information for program %s", name)
		}

		for f, live := range r.Funcs() {
			if live {
				continue
			}

			var last *asm.Instruction
			for i, ins := range f.Instructions(p.Instructions) {
				n := nop(ins)
				if i == 0 {
					// Keep symbol and BTF func info on the function's entry.
					n = n.WithMetadata(ins.Metadata).
						WithSource(asm.Comment(fmt.Sprintf("%s // (unused bpf2bpf function)", ins.Source())))
				}
				*ins = n
				last = ins
			}
			if last == nil {
				return fmt.Errorf("function %s in program %s has no instructions", f.Name(), name)
			}

			// Functions must end in an exit. The last insn of a function is always
			// single-width (exit or jump), so this doesn't change instruction offsets.
			*last = asm.Return().WithMetadata(last.Metadata)

			if logger != nil {
				logger.Debug("Replaced unused function with nop sled",
					logfields.Prog, name,
					logfields.Name, f.Name(),
				)
			}
		}
	}

	return nil
}
