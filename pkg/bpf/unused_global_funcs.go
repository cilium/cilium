// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// removeUnusedGlobalFuncs stubs out global BPF functions whose entry blocks are
// unreachable. This prevents the pre-6.8 kernel verifier from independently
// verifying those functions, which in turn allows their maps to be pruned by
// [removeUnusedMaps].
//
// Each dead global function's instruction range is replaced in-place with a
// minimal stub: mov r0, 0 followed by exit. The stub is trivially valid for the
// verifier's independent pass and contains no map references.
func removeUnusedGlobalFuncs(spec *ebpf.CollectionSpec, reach reachables, logger *slog.Logger) error {
	if reach == nil {
		return fmt.Errorf("reachability information is required")
	}

	var stubbed []string

	for name := range spec.Programs {
		r, ok := reach[name]
		if !ok {
			return fmt.Errorf("missing reachability information for program %s", name)
		}

		ranges := r.DeadGlobalFuncRanges()
		if len(ranges) == 0 {
			continue
		}

		insns := r.ProgramSpec.Instructions
		for _, rng := range ranges {
			start, end := rng[0], rng[1]

			sym := insns[start].Symbol()
			fn := btf.FuncMetadata(&insns[start])
			src := insns[start].Source()

			stubbed = append(stubbed, sym)

			if start == end {
				insns[start] = withFuncInfo(withSource(asm.Return().WithSymbol(sym), src), fn)
				continue
			}

			// First instruction keeps the symbol label, BTF metadata, and source.
			insns[start] = withFuncInfo(withSource(asm.Mov.Imm(asm.R0, 0).WithSymbol(sym), src), fn)

			for i := start + 1; i < end; i++ {
				insns[i] = asm.Mov.Imm(asm.R0, 0)
			}

			insns[end] = asm.Return()
		}
	}

	if logger != nil && len(stubbed) > 0 {
		logger.Debug("Stubbed out unreachable global functions", logfields.Programs, stubbed)
	}

	return nil
}

func withFuncInfo(ins asm.Instruction, fn *btf.Func) asm.Instruction {
	if fn != nil {
		return btf.WithFuncMetadata(ins, fn)
	}
	return ins
}

func withSource(ins asm.Instruction, src fmt.Stringer) asm.Instruction {
	if src != nil {
		return ins.WithSource(src)
	}
	return ins
}
