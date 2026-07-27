//go:build generate

//go:generate go run $GOFILE

// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

// Package main generates a lookup table for longest-prefix-match (LPM) operations
// in the BART routing table.
//
// This generator creates a precomputed lookup table (LookupTbl) that enables fast
// prefix matching by replacing iterative backtracking with a single bitset intersection.
//
// The core idea:
//
// In a complete binary tree representation of prefixes, finding the longest matching
// prefix requires checking a node and all its ancestors (parent, grandparent, etc.).
// Instead of iterating through ancestors at runtime (idx >>= 1 in a loop), this table
// precomputes all ancestors for each index.
//
// Binary tree structure:
//   - Each index i has a parent at i>>1 (integer division by 2)
//   - Index 1 is the root (represents the default route)
//   - Indices 2-255 form a 7-level binary tree
//
// Example: Index 13 (binary: 0b1101) has ancestors:
//   - 13 itself (0b1101)
//   - 6  = 13>>1 (0b0110) - parent
//   - 3  = 6>>1  (0b0011) - grandparent
//   - 1  = 3>>1  (0b0001) - root
//
// With this table, checking if any ancestor exists in a node's prefix set becomes:
//
//	node.prefixes.Intersects(&LookupTbl[idx])
//
// instead of a loop with multiple Test() calls.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/gaissmai/bart/internal/bitset"
)

var (
	thisFname = os.Getenv("GOFILE")
	outFname  = "lookuptblgenerated.go"
)

// data holds the template variables for code generation.
// The LookupTbl field is populated immediately with the generated table string
var data = struct {
	File      string
	LookupTbl string
}{
	File:      thisFname,
	LookupTbl: genLookupTbl(),
}

// colored prefix for informational and error messages
const (
	INFO = "\x1b[34mINFO:\x1b[0m"
	DIE  = "\x1b[31mERROR:\x1b[0m"
)

func main() {
	outFile, err := os.Create(outFname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", DIE, err)
		os.Exit(1)
	}

	// Parse the template ...
	t := template.Must(template.New("foo").Parse(codeTemplate))

	// ... and execute it with our data
	err = t.Execute(outFile, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", DIE, err)
		_ = outFile.Close()
		os.Exit(1)
	}

	// Ensure the file is properly closed before formatting
	if err := outFile.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", DIE, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "%s ✓ Generated %s\n", INFO, outFname)

	// Run goimports to organize imports and format the code
	goimports := exec.Command("goimports", "-w", outFname)
	fmt.Fprintf(os.Stdout, "%s Running goimports on %s\n", INFO, outFname)
	if out, err := goimports.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "%s %s\n", DIE, string(out))
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "%s ✓ goimports completed\n", INFO)

	// Run gofumpt for additional formatting consistency
	gofumpt := exec.Command("gofumpt", "-w", outFname)
	fmt.Fprintf(os.Stdout, "%s Running gofumpt on %s\n", INFO, outFname)
	if out, err := gofumpt.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "%s %s\n", DIE, string(out))
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "%s ✓ gofumpt completed\n", INFO)

	fmt.Println()
}

// genLookupTbl generates the lookup table as a formatted string.
//
// For each index i (1-255), the table stores a bitset containing:
//   - i itself
//   - all binary ancestors of i (i>>1, i>>2, i>>3, ...)
//
// Example: For index 13 (binary: 1101):
//   - Set bit 13 (1101)
//   - Set bit 6  (0110) = 13>>1
//   - Set bit 3  (0011) = 6>>1
//   - Set bit 1  (0001) = 3>>1
//
// This precomputation allows replacing a loop of bitset tests
// with a single bitset intersection operation during longest-prefix-match.

// genLookupTbl generates the lookup table as a formatted string.
//
// For each index i (1-255), the table stores a BitSet256 containing:
//   - i itself (the current node)
//   - all binary ancestors of i (obtained by repeatedly right-shifting: i>>1, i>>2, ...)
//
// The algorithm walks up the binary tree from each leaf to the root (index 1).
// Each right-shift operation (i >>= 1) moves from a child to its parent node:
//   - Even indices (LSB=0) are left children: parent = i/2
//   - Odd indices (LSB=1) are right children: parent = (i-1)/2
//   - Both cases are handled by integer division via right-shift
//
// Example walkthrough for index 13 (binary: 0b00001101):
//
//	Iteration 1: i=13 (0b00001101) => Set bit 13
//	Iteration 2: i=6  (0b00000110) => Set bit 6  (parent of 13)
//	Iteration 3: i=3  (0b00000011) => Set bit 3  (parent of 6)
//	Iteration 4: i=1  (0b00000001) => Set bit 1  (root)
//	Iteration 5: i=0  → Loop terminates
//
// Result: BitSet256 with bits {1, 3, 6, 13} set
//
// This allows longest-prefix-match to be computed with a single bitset intersection:
//
//	// Fast O(1) check using precomputed ancestors
//	return node.prefixes.Intersects(&LookupTbl[idx])
//
// instead of iterative backtracking:
//
//	// Slow O(log n) loop checking each ancestor individually
//	for ; idx > 0; idx >>= 1 {
//	    if node.prefixes.Test(idx) {
//	        return true
//	    }
//	}
//
// The generated string is formatted for embedding into Go source code.
func genLookupTbl() string {
	// Initialize the lookup table with 256 entries (one per uint8 value)
	lookupTbl := [256]bitset.BitSet256{}

	for idx := 1; idx <= 255; idx++ {
		// Walk up the binary tree by repeatedly right-shifting
		// Each iteration moves to the parent node (idx >> 1)
		for i := idx; i > 0; i >>= 1 {
			lookupTbl[idx].Set(uint8(i))
		}
	}

	// Convert the lookup table to a formatted string for the generated code
	builder := strings.Builder{}

	// Index 0 is invalid (no valid prefix maps to 0)
	fmt.Fprintf(&builder, "  /* idx: %3d */ %#v, // %s\n", 0, lookupTbl[0], "invalid")

	// Format each valid index with its bitset and the list of set bits, e.g.
	// /* idx:  13 */ {0x204a, 0x0, 0x0, 0x0}, // [1 3 6 13]
	for idx := 1; idx < 256; idx++ {
		fmt.Fprintf(&builder, "  /* idx: %3d */ %#v, // %v\n", idx, lookupTbl[idx], lookupTbl[idx].Bits())
	}

	return builder.String()
}

// codeTemplate is the Go source template for the generated lookuptbl_gen.go file.
// It embeds the precomputed lookup table and includes comprehensive documentation
// about its structure, usage, and performance benefits.
//
// The template defines:
//   - Package-level documentation explaining the LPM optimization
//   - The LookupTbl variable with all 256 precomputed bitsets
//   - Usage examples comparing the fast (Intersects) vs slow (loop) approach
//   - Warnings about not mutating the read-only table
const codeTemplate = `// Code generated by {{.File}}; DO NOT EDIT.

// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

// Package lpm (longest-prefix-match) contains the lookup table with which
// the backtracking for the lpm in the complete binary tree of the prefixes
// can be replaced by a fast bitset operation.
package lpm

// LookupTbl is a precomputed read‑only table used in hot paths.
//
// It allows a one-shot bitset intersection algorithm:
// Each entry i encodes i and all its binary ancestors (i>>1, i>>2, ...).
//
// idx must be the uint8 produced by art.OctetToIdx or art.PfxToIdx (0 is invalid).
//
// Usage:
//
//	func (n *bartNode[V]) contains(idx uint8) bool {
//		return n.prefixes.Intersects(&lpm.LookupTbl[idx])
//	}
//
// instead of a sequence of single bitset tests:
//
//	func (n *bartNode[V]) contains(idx uint8) bool {
//		for ; idx > 0; idx >>= 1 {
//			if n.prefixes.Test(idx) {
//				return true
//			}
//		}
//		return false
//	}
//
// DO NOT MUTATE: Precomputed read‑only table used in hot paths.
//
//nolint:gochecknoglobals
var LookupTbl = [256]bitset.BitSet256{
{{.LookupTbl}} }`
