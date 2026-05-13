//go:build generate

//go:generate go run $GOFILE

// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

// Package main generates lookup tables for route allocation in the BART routing table.
//
// This generator creates two precomputed lookup tables (PfxRoutesLookupTbl and
// FringeRoutesLookupTbl) that enable fast prefix coverage queries. Each table maps
// a base index (1..255) to a bitset containing all more specific indices covered
// by that prefix.
//
// The tables model a complete binary tree where:
//   - Indices 1..255 represent prefixes up to /7
//   - Indices 256..511 represent /8 prefixes (stored separately as "fringe")
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
	outFname  = "allotroutesgenerated.go"
)

var (
	// prefixAllotTbl holds the bitsets for indices 1..255 (prefixes up to /7).
	// For each index idx, the bitset contains all descendant indices in the
	// range 1..255 that are covered by the prefix at idx.
	prefixAllotTbl [256]bitset.BitSet256

	// fringeAllotTbl holds the bitsets for indices 1..255, but tracks descendants
	// in the range 256..511 (/8 prefixes). The bitset at index idx contains all
	// /8 fringe indices (minus 256 offset) covered by the prefix at idx.
	fringeAllotTbl [256]bitset.BitSet256
)

// data holds the template variables for code generation
var data struct {
	File             string
	PrefixAllotTable string
	FringeAllotTable string
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

	// Generate both lookup tables using the stack-based algorithm
	prefixAllotTbl, fringeAllotTbl = genAllotTables()

	// Populate template data
	data.File = thisFname
	data.PrefixAllotTable = asString(prefixAllotTbl)
	data.FringeAllotTable = asString(fringeAllotTbl)

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

// genAllotTables generates both prefix and fringe allocation lookup tables.
//
// For each base index idx (1..255), it performs a breadth-first traversal of the
// complete binary tree rooted at idx, collecting all descendant indices. The
// traversal uses a stack-based approach instead of recursion.
//
// The algorithm:
//  1. Start with the root index idx in the stack
//  2. For each index j in the stack:
//     - If j < 256: add j to prefixAllotTbl[idx]
//     - If j >= 256: add (j-256) to fringeAllotTbl[idx]
//     - If j < 256: push children (2*j and 2*j+1) onto the stack
//  3. Continue until the stack is exhausted
//
// This builds a complete binary tree where each node knows all its descendants,
// split into two ranges: [1..255] and [256..511].
//
// Returns the prefix table (indices 1..255) and fringe table (indices 256..511).
func genAllotTables() (prefix, fringe [256]bitset.BitSet256) {
	prefixAllotTbl := [256]bitset.BitSet256{}
	fringeAllotTbl := [256]bitset.BitSet256{}

	for idx := 1; idx < 256; idx++ {
		// allot algorithm, stack based instead of recursion
		stack := make([]int, 0, 512)
		stack = append(stack, idx)

		for i := 0; i < len(stack); i++ {
			j := stack[i]
			if j < 256 {
				prefixAllotTbl[idx].Set(uint8(j))
			} else {
				fringeAllotTbl[idx].Set(uint8(j - 256))
			}

			// max j is 511, so stop the duplication at 256 and above
			if j >= 256 {
				continue
			}

			// build a complete binary tree
			// left:  j*2
			// right: (j*2)+1
			stack = append(stack, j<<1, (j<<1)+1)
		}
	}
	return prefixAllotTbl, fringeAllotTbl
}

// asString converts a lookup table to a formatted Go source string.
//
// Each entry in the table is formatted as:
//
//	/* idx: N */ BitSet256{...}, // [list of set bits]
//
// For bitsets with 10 or more set bits, the list is truncated with "..." to
// keep the generated code readable. Index 0 is marked as "invalid" since no
// valid prefix maps to base index 0 in the BART structure.
//
// The returned string is ready to be embedded into the generated Go file.
func asString(tbl [256]bitset.BitSet256) string {
	builder := strings.Builder{}

	// Index 0 is invalid (no valid prefix maps to 0)
	fmt.Fprintf(&builder, "  /* idx: %3d */ %#v, // %s\n", 0, tbl[0], "invalid")

	// Format each valid index with its bitset and the list of set bits, e.g.
	// /* idx:  13 */ {0x204a, 0x0, 0x0, 0x0}, // [1 3 6 13]
	for idx := 1; idx < 256; idx++ {
		fmt.Fprintf(&builder, "  /* idx: %3d */ %#v, // ", idx, tbl[idx])

		bits := tbl[idx].Bits()
		if len(bits) < 10 {
			fmt.Fprintf(&builder, "%v\n", bits)
		} else {
			fmt.Fprint(&builder, "[")
			for _, bit := range bits[:5] {
				fmt.Fprintf(&builder, "%d, ", bit)
			}
			fmt.Fprintln(&builder, "... ]")
		}
	}

	return builder.String()
}

// codeTemplate is the Go source template for the generated allotRoutes_gen.go file.
// It embeds the precomputed lookup tables and includes documentation about
// their structure and usage.
const codeTemplate = `// Code generated by {{.File}}; DO NOT EDIT.

// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package allot

// PfxRoutesLookupTbl is a lookup table of BitSet256 entries.
//
// It maps a baseIndex (1..255) to a bitset that contains all more
// specific baseIndices that are covered by the prefix at that index.
//
// The idea:
//
//	If prefix P has baseIndex idx, then P covers all prefixes in the subtree
//	rooted at idx. This table enumerates and encodes those indices.
//
// The table is split:
//   - PfxRoutesLookupTbl holds prefixes up to /7
//   - FringeRoutesLookupTbl holds /8 prefixes
//
// This structure allows for very fast set inclusion checks using simple bitwise AND.
//
//nolint:gochecknoglobals // Precomputed read‑only table used in hot paths.
var PfxRoutesLookupTbl = [256]bitset.BitSet256{
{{.PrefixAllotTable}} }

// FringeRoutesLookupTbl, the second 256 Bits, see also the PfxRoutesLookupTbl for the first 256 Bits
// we split 512 bits into 2×256 to leverage BitSet256 optimizations.
//
//nolint:gochecknoglobals // Precomputed read‑only table used in hot paths.
var FringeRoutesLookupTbl = [256]bitset.BitSet256{
{{.FringeAllotTable}} }
`
