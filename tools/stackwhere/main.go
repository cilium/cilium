// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"debug/dwarf"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/cilium/cilium/tools/stackwhere/dwarf/op"
)

var flagCallStack = flag.Bool("call-stack", false, "Show the full callstack of a variable")

// Stackwhere is a tool to help understand where stack usage in a given BPF program is coming from.
// It parses the DWARF debug information in a given binary to find the stack offsets where variables are stored.
// It displays all variables stored at particular stack offsets and some metadata like their size and where they
// are declared.
//
// Stackwhere can also give a summary of the total stack usage of each BPF program in the binary by not specifying
// a specific function name.

func main() {
	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: ./stackwhere <binary> [function]\n")
		fmt.Fprintf(os.Stderr, "Stackwhere analyzes the given binary and shows you where stack usage is coming from.\n")
		os.Exit(1)
	}

	tree, err := newDWARFTree(flag.Args()[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse DWARF data: %v\n", err)
		os.Exit(1)
	}

	if len(flag.Args()) >= 2 {
		showStackSlots(tree, flag.Args()[1])
	} else {
		showProgramStackUsage(tree)
	}
}

func showStackSlots(tree *tree, functionName string) {
	usage := getStackSlotUsage(tree, functionName)
	for offset, slots := range usage {
		fmt.Printf("R10-%d:\n", offset)
		for _, slot := range slots {
			fmt.Printf("  %d - %s @ %s\n", slot.byteSize, slot.name, slot.fileCol)
			if *flagCallStack {
				for _, entry := range slot.callstack {
					fmt.Printf("    %s @ %s\n", entry.name, entry.fileCol)
				}
			}
		}
	}
}

type slotUsage struct {
	name      string
	byteSize  int64
	fileCol   string
	callstack []callStackEntry
}

type callStackEntry struct {
	name    string
	fileCol string
}

func getStackSlotUsage(tree *tree, functionName string) map[int64][]slotUsage {
	result := map[int64][]slotUsage{}
	for _, n := range tree.byType[dwarf.TagSubprogram] {
		name := n.entry.Val(dwarf.AttrName)
		if name == nil {
			continue
		}
		if name.(string) != functionName {
			continue
		}

		entrypoint := n
		stackMap := map[int64][]*node{}
		visitPrefixOrder(n, func(n *node) {
			// We are interested in variables and function parameters since those are the things that can be stored on
			// the stack.
			if n.entry.Tag != dwarf.TagVariable && n.entry.Tag != dwarf.TagFormalParameter {
				return
			}

			// If the current variable lives on the stack, add it to the map of stack offsets to variables that live at that offset.
			offsets := stackOffsets(n)
			if len(offsets) > 0 {
				for _, offset := range offsets {
					if !slices.Contains(stackMap[offset], n) {
						stackMap[offset] = append(stackMap[offset], n)
					}
				}
			}
		})

		// Print the variables grouped by their stack offset, sorted by largest byte size first and then name.
		for _, offset := range slices.SortedFunc(maps.Keys(stackMap), func(a, b int64) int {
			return int(b - a)
		}) {
			nodes := stackMap[offset]
			slices.SortFunc(nodes, func(a, b *node) int {
				sz := int(b.ByteSize()) - int(a.ByteSize())
				if sz != 0 {
					return sz
				}

				return strings.Compare(a.Name(), b.Name())
			})

			// Remove duplicates that can occur, for example when a function is inlined multiple times and it
			// ends up reusing the same stack space.
			nodes = slices.CompactFunc(nodes, func(a, b *node) bool {
				return a.Name() == b.Name() && a.ByteSize() == b.ByteSize() && a.FileCol() == b.FileCol()
			})
			for _, n := range nodes {
				callstack := []callStackEntry{}

				parents := []*node{}
				p := n
				for p != nil {
					p = p.parent
					parents = append(parents, p)
					if p == entrypoint {
						break
					}
				}
				for _, parent := range parents {
					if parent.Name() == "" {
						continue
					}
					callstack = append(callstack, callStackEntry{
						name:    parent.Name(),
						fileCol: parent.FileCol(),
					})
				}

				result[offset] = append(result[offset], slotUsage{
					name:      n.Name(),
					byteSize:  n.ByteSize(),
					fileCol:   n.FileCol(),
					callstack: callstack,
				})
			}
		}
	}

	return result
}

func showProgramStackUsage(tree *tree) {
	stackUsagePerProgram := map[string]int64{}
	for _, prog := range tree.byType[dwarf.TagSubprogram] {
		if !isBPFProgram(prog) {
			continue
		}

		stackUsagePerProgram[prog.Name()] = getProgramStackUsage(prog)
	}

	// Sort by stack usage, largest first, and then by name, and print.
	keys := slices.Collect(maps.Keys(stackUsagePerProgram))
	slices.SortFunc(keys, func(a, b string) int {
		return int(stackUsagePerProgram[b] - stackUsagePerProgram[a])
	})
	for _, prog := range keys {
		fmt.Printf("%3d bytes - %s\n", stackUsagePerProgram[prog], prog)
	}
}

func getProgramStackUsage(prog *node) int64 {
	largestOffset := int64(0)
	lastSize := int64(0)
	visitPrefixOrder(prog, func(n *node) {
		// Only consider variables and function parameters since those are the things that can be stored on the stack.
		if n.entry.Tag != dwarf.TagVariable && n.entry.Tag != dwarf.TagFormalParameter {
			return
		}

		// Find all stack offsets used by this variable.
		offsets := stackOffsets(n)
		if len(offsets) == 0 {
			return
		}

		// If this was the largest stack offset we've seen so far, then the total stack usage must be at least
		// large enough to fit this variable. If this variable has the same largest offset as a previous variable,
		// but is larger than that previous variable, then the total stack usage must be increased to fit this variable.
		sz := n.ByteSize()
		for _, offset := range offsets {
			if offset > largestOffset {
				largestOffset = offset
				lastSize = sz
			}
			if offset == largestOffset && sz > lastSize {
				lastSize = sz
			}
		}
	})

	// Stack usage is always a multiple of 8 bytes, so round up to the nearest multiple of 8.
	stackUsage := largestOffset + lastSize
	if stackUsage%8 != 0 {
		stackUsage = ((stackUsage / 8) + 1) * 8
	}

	return stackUsage
}

func stackOffsets(n *node) []int64 {
	offsets := []int64{}

	// DWARF can express variable locations in two ways: as a single location expression or
	// as a list of location expressions that are valid for different ranges of instructions.
	if location, err := n.Location(); err == nil && location != nil {
		// Loop over all instructions, see if any of them reference the frame base register, and thus some
		// offset into the stack.
		for _, locOp := range location {
			if locOp.Opcode == op.DW_OP_fbreg {
				if !slices.Contains(offsets, locOp.Args[0].(int64)) {
					offsets = append(offsets, locOp.Args[0].(int64))
				}
			}
		}
	} else if locList, err := n.LocationList(); err == nil && locList != nil {
		// Loop over all entries in the locations list, each entry is valid for a specific range of instructions
		// so a single variable may live in different places (registers, stack, etc) at different points in
		// the program.
		for _, entry := range locList.entries {
			// The base address + offset pair entries seem to be the only ones used in BPF object files.
			switch e := entry.(type) {
			case lleOffsetPair:
				// Loop over all instructions, see if any of them reference the frame base register, and thus some
				// offset into the stack.
				for _, locOp := range e.ops {
					if locOp.Opcode == op.DW_OP_fbreg || locOp.Opcode == op.DW_OP_breg10 {
						if !slices.Contains(offsets, locOp.Args[0].(int64)) {
							offsets = append(offsets, locOp.Args[0].(int64))
						}
					}
				}
			}
		}
	}

	slices.Sort(offsets)
	return slices.Compact(offsets)
}

func isBPFProgram(n *node) bool {
	if n.entry.Tag != dwarf.TagSubprogram {
		return false
	}

	if n.entry.Val(dwarf.AttrName) == nil {
		return false
	}

	if n.entry.Val(dwarf.AttrInline) != nil {
		return false
	}

	if n.entry.Val(dwarf.AttrType) == nil {
		return false
	}

	return true
}
