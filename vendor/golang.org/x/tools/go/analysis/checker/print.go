// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

// This file defines helpers for printing analysis results.
// They should all be pure functions.

import (
	"bytes"
	"fmt"
	"go/token"
	"io"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/internal/analysisflags"
)

// PrintText emits diagnostics as plain text to w.
//
// If contextLines is nonnegative, it also prints the
// offending line, plus that many lines of context
// before and after the line.
func (g *Graph) PrintText(w io.Writer, contextLines int) error {
	return writeTextDiagnostics(w, g.Roots, contextLines)
}

func writeTextDiagnostics(w io.Writer, roots []*Action, contextLines int) error {
	// De-duplicate diagnostics by position (not token.Pos) to
	// avoid double-reporting in source files that belong to
	// multiple packages, such as foo and foo.test.
	// (We cannot assume that such repeated files were parsed
	// only once and use syntax nodes as the key.)
	type key struct {
		pos token.Position
		end token.Position
		*analysis.Analyzer
		message string
	}
	seen := make(map[key]bool)

	// TODO(adonovan): opt: plumb errors back from PrintPlain and avoid buffer.
	buf := new(bytes.Buffer)
	forEach(roots, func(act *Action) error {
		if act.Err != nil {
			fmt.Fprintf(w, "%s: %v\n", act.Analyzer.Name, act.Err)
		} else if act.IsRoot {
			for _, diag := range act.Diagnostics {
				// We don't display Analyzer.Name/diag.Category
				// as most users don't care.

				posn := act.Package.Fset.Position(diag.Pos)
				end := act.Package.Fset.Position(diag.End)
				k := key{posn, end, act.Analyzer, diag.Message}
				if seen[k] {
					continue // duplicate
				}
				seen[k] = true

				analysisflags.PrintPlain(buf, act.Package.Fset, contextLines, diag)
			}
		}
		return nil
	})
	_, err := w.Write(buf.Bytes())
	return err
}

// PrintJSON emits diagnostics in JSON form to w.
// Diagnostics are shown only for the root nodes,
// but errors (if any) are shown for all dependencies.
func (g *Graph) PrintJSON(w io.Writer) error {
	return writeJSONDiagnostics(w, g.Roots)
}

func writeJSONDiagnostics(w io.Writer, roots []*Action) error {
	tree := make(analysisflags.JSONTree)
	forEach(roots, func(act *Action) error {
		var diags []analysis.Diagnostic
		if act.IsRoot {
			diags = act.Diagnostics
		}
		tree.Add(act.Package.Fset, act.Package.ID, act.Analyzer.Name, diags, act.Err)
		return nil
	})
	return tree.Print(w)
}
