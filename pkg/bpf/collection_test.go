// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestInlineGlobalData(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		ByteOrder: binary.LittleEndian,
		Maps: map[string]*ebpf.MapSpec{
			globalDataMap: {
				Contents: []ebpf.MapKV{{Value: []byte{
					0x0, 0x0, 0x0, 0x80,
					0x1, 0x0, 0x0, 0x0,
				}}},
			},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"prog1": {
				Instructions: asm.Instructions{
					// Pseudo-load at offset 0. This Instruction would have func_info when
					// read from an ELF, so validate Metadata preservation after inlining
					// global data.
					asm.LoadMapValue(asm.R0, 0, 0).WithReference(globalDataMap).WithSymbol("func1"),
					// Pseudo-load at offset 4.
					asm.LoadMapValue(asm.R0, 0, 4).WithReference(globalDataMap),
					asm.Return(),
				},
			},
		},
	}

	if err := inlineGlobalData(spec); err != nil {
		t.Fatal(err)
	}

	ins := spec.Programs["prog1"].Instructions[0]
	if want, got := 0x80000000, int(ins.Constant); want != got {
		t.Errorf("unexpected Instruction constant: want: 0x%x, got: 0x%x", want, got)
	}

	if want, got := "func1", ins.Symbol(); want != got {
		t.Errorf("unexpected Symbol value of Instruction: want: %s, got: %s", want, got)
	}

	ins = spec.Programs["prog1"].Instructions[1]
	if want, got := 0x1, int(ins.Constant); want != got {
		t.Errorf("unexpected Instruction constant: want: 0x%x, got: 0x%x", want, got)
	}
}
