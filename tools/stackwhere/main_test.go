// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bytes"
	"debug/dwarf"
	_ "embed"
	"slices"
	"testing"
)

//go:embed testdata/stacktest.o
var stacktest []byte

func TestStackSlotUsage(t *testing.T) {
	tree, err := newDWARFTreeReader(bytes.NewReader(stacktest))
	if err != nil {
		t.Fatalf("failed to parse DWARF data: %v", err)
	}

	usage := getStackSlotUsage(tree, "cil_entry")
	r10min0 := usage[0]
	if len(r10min0) != 3 {
		t.Fatalf("unexpected 3 variables at R10-0, got: %v", r10min0)
	}
	for _, v := range []string{"a", "b", "c"} {
		idx := slices.IndexFunc(r10min0, func(su slotUsage) bool {
			return su.name == v
		})
		if idx == -1 {
			t.Fatalf("expected variable '%s' at R10-0, got: %v", v, r10min0)
		}

		if len(r10min0[idx].callstack) != 1 {
			t.Fatalf("expected 1 callstack entry for variable '%s', got: %v", v, r10min0[idx].callstack)
		}
		if r10min0[idx].callstack[0].name != "cil_entry" {
			t.Fatalf("expected callstack entry 'cil_entry' for variable '%s', got: %v", v, r10min0[idx].callstack[0])
		}
	}

	r10min32 := usage[32]
	if len(r10min32) != 3 {
		t.Fatalf("unexpected 3 variables at R10-32, got: %v", r10min32)
	}
	for _, v := range [][2]string{{"two_inlined_a", "inlined_a"}, {"two_inlined_b", "inlined_b"}, {"two_inlined_c", "inlined_c"}} {
		idx := slices.IndexFunc(r10min32, func(su slotUsage) bool {
			return su.name == v[0]
		})
		if idx == -1 {
			t.Fatalf("expected variable '%s' at R10-32, got: %v", v[0], r10min32)
		}

		if len(r10min32[idx].callstack) != 2 {
			t.Fatalf("expected 2 callstack entries for variable '%s', got: %v", v[0], r10min32[idx].callstack)
		}
		if r10min32[idx].callstack[0].name != v[1] {
			t.Fatalf("expected callstack entry '%s' for variable '%s', got: %v", v[1], v[0], r10min32[idx].callstack[0])
		}
		if r10min32[idx].callstack[1].name != "cil_entry" {
			t.Fatalf("expected callstack entry 'cil_entry' for variable '%s', got: %v", v[0], r10min32[idx].callstack[1])
		}
	}

	r10min48 := usage[48]
	if len(r10min48) != 1 {
		t.Fatalf("unexpected 1 variable at R10-48, got: %v", r10min48)
	}
	if r10min48[0].name != "one_inlined_d" {
		t.Fatalf("expected variable 'one_inlined_d' at R10-48, got: %v", r10min48[0])
	}
	if len(r10min48[0].callstack) != 3 {
		t.Fatalf("expected 3 callstack entries for variable 'one_inlined_d', got: %v", r10min48[0].callstack)
	}
	if r10min48[0].callstack[0].name != "inlined_d" {
		t.Fatalf("expected callstack entry 'inlined_d' for variable 'one_inlined_d', got: %v", r10min48[0].callstack[0])
	}
	if r10min48[0].callstack[1].name != "inlined_c" {
		t.Fatalf("expected callstack entry 'inlined_c' for variable 'one_inlined_d', got: %v", r10min48[0].callstack[1])
	}
	if r10min48[0].callstack[2].name != "cil_entry" {
		t.Fatalf("expected callstack entry 'cil_entry' for variable 'one_inlined_d', got: %v", r10min48[0].callstack[2])
	}
}

func TestProgramStackUsage(t *testing.T) {
	tree, err := newDWARFTreeReader(bytes.NewReader(stacktest))
	if err != nil {
		t.Fatalf("failed to parse DWARF data: %v", err)
	}

	count := 0
	for _, n := range tree.byType[dwarf.TagSubprogram] {
		if !isBPFProgram(n) {
			continue
		}

		count++
		stackUsage := getProgramStackUsage(n)
		if stackUsage != 56 {
			t.Fatalf("expected program stack usage of 56 bytes, got: %d", stackUsage)
		}
	}
	if count != 1 {
		t.Fatalf("expected to find 1 BPF program, found: %d", count)
	}
}
