// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package internal/checker defines various implementation helpers for
// the singlechecker and multichecker packages, which provide the
// complete main function for an analysis driver executable
// based on go/packages.
//
// (Note: it is not used by the public 'checker' package, since the
// latter provides a set of pure functions for use as building blocks.)
package checker

// TODO(adonovan): publish the JSON schema in go/analysis or analysisjson.

import (
	"flag"
	"fmt"
	"go/format"
	"go/token"
	"io"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strings"
	"time"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/analysis/internal/analysisflags"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/internal/diff"
	"golang.org/x/tools/internal/robustio"
)

var (
	// Debug is a set of single-letter flags:
	//
	//	f	show [f]acts as they are created
	// 	p	disable [p]arallel execution of analyzers
	//	s	do additional [s]anity checks on fact types and serialization
	//	t	show [t]iming info (NB: use 'p' flag to avoid GC/scheduler noise)
	//	v	show [v]erbose logging
	//
	Debug = ""

	// Log files for optional performance tracing.
	CPUProfile, MemProfile, Trace string

	// IncludeTests indicates whether test files should be analyzed too.
	IncludeTests = true

	// Fix determines whether to apply all suggested fixes.
	Fix bool
)

// RegisterFlags registers command-line flags used by the analysis driver.
func RegisterFlags() {
	// When adding flags here, remember to update
	// the list of suppressed flags in analysisflags.

	flag.StringVar(&Debug, "debug", Debug, `debug flags, any subset of "fpstv"`)

	flag.StringVar(&CPUProfile, "cpuprofile", "", "write CPU profile to this file")
	flag.StringVar(&MemProfile, "memprofile", "", "write memory profile to this file")
	flag.StringVar(&Trace, "trace", "", "write trace log to this file")
	flag.BoolVar(&IncludeTests, "test", IncludeTests, "indicates whether test files should be analyzed, too")

	flag.BoolVar(&Fix, "fix", false, "apply all suggested fixes")
}

// Run loads the packages specified by args using go/packages,
// then applies the specified analyzers to them.
// Analysis flags must already have been set.
// Analyzers must be valid according to [analysis.Validate].
// It provides most of the logic for the main functions of both the
// singlechecker and the multi-analysis commands.
// It returns the appropriate exit code.
func Run(args []string, analyzers []*analysis.Analyzer) int {
	if CPUProfile != "" {
		f, err := os.Create(CPUProfile)
		if err != nil {
			log.Fatal(err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal(err)
		}
		// NB: profile won't be written in case of error.
		defer pprof.StopCPUProfile()
	}

	if Trace != "" {
		f, err := os.Create(Trace)
		if err != nil {
			log.Fatal(err)
		}
		if err := trace.Start(f); err != nil {
			log.Fatal(err)
		}
		// NB: trace log won't be written in case of error.
		defer func() {
			trace.Stop()
			log.Printf("To view the trace, run:\n$ go tool trace view %s", Trace)
		}()
	}

	if MemProfile != "" {
		f, err := os.Create(MemProfile)
		if err != nil {
			log.Fatal(err)
		}
		// NB: memprofile won't be written in case of error.
		defer func() {
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				log.Fatalf("Writing memory profile: %v", err)
			}
			f.Close()
		}()
	}

	// Load the packages.
	if dbg('v') {
		log.SetPrefix("")
		log.SetFlags(log.Lmicroseconds) // display timing
		log.Printf("load %s", args)
	}

	// Optimization: if the selected analyzers don't produce/consume
	// facts, we need source only for the initial packages.
	allSyntax := needFacts(analyzers)
	initial, err := load(args, allSyntax)
	if err != nil {
		log.Print(err)
		return 1
	}

	pkgsExitCode := 0
	// Print package and module errors regardless of RunDespiteErrors.
	// Do not exit if there are errors, yet.
	if n := packages.PrintErrors(initial); n > 0 {
		pkgsExitCode = 1
	}

	var factLog io.Writer
	if dbg('f') {
		factLog = os.Stderr
	}

	// Run the analysis.
	opts := &checker.Options{
		SanityCheck: dbg('s'),
		Sequential:  dbg('p'),
		FactLog:     factLog,
	}
	if dbg('v') {
		log.Printf("building graph of analysis passes")
	}
	graph, err := checker.Analyze(analyzers, initial, opts)
	if err != nil {
		log.Print(err)
		return 1
	}

	// Apply all fixes from the root actions.
	if Fix {
		if err := applyFixes(graph.Roots); err != nil {
			// Fail when applying fixes failed.
			log.Print(err)
			return 1
		}
	}

	// Print the results. If !RunDespiteErrors and there
	// are errors in the packages, this will have 0 exit
	// code. Otherwise, we prefer to return exit code
	// indicating diagnostics.
	if diagExitCode := printDiagnostics(graph); diagExitCode != 0 {
		return diagExitCode // there were diagnostics
	}
	return pkgsExitCode // package errors but no diagnostics
}

// printDiagnostics prints diagnostics in text or JSON form
// and returns the appropriate exit code.
func printDiagnostics(graph *checker.Graph) (exitcode int) {
	// Print the results.
	// With -json, the exit code is always zero.
	if analysisflags.JSON {
		if err := graph.PrintJSON(os.Stdout); err != nil {
			return 1
		}
	} else {
		if err := graph.PrintText(os.Stderr, analysisflags.Context); err != nil {
			return 1
		}

		// Compute the exit code.
		var numErrors, rootDiags int
		// TODO(adonovan): use "for act := range graph.All() { ... }" in go1.23.
		graph.All()(func(act *checker.Action) bool {
			if act.Err != nil {
				numErrors++
			} else if act.IsRoot {
				rootDiags += len(act.Diagnostics)
			}
			return true
		})
		if numErrors > 0 {
			exitcode = 1 // analysis failed, at least partially
		} else if rootDiags > 0 {
			exitcode = 3 // successfully produced diagnostics
		}
	}

	// Print timing info.
	if dbg('t') {
		if !dbg('p') {
			log.Println("Warning: times are mostly GC/scheduler noise; use -debug=tp to disable parallelism")
		}

		var list []*checker.Action
		var total time.Duration
		// TODO(adonovan): use "for act := range graph.All() { ... }" in go1.23.
		graph.All()(func(act *checker.Action) bool {
			list = append(list, act)
			total += act.Duration
			return true
		})

		// Print actions accounting for 90% of the total.
		sort.Slice(list, func(i, j int) bool {
			return list[i].Duration > list[j].Duration
		})
		var sum time.Duration
		for _, act := range list {
			fmt.Fprintf(os.Stderr, "%s\t%s\n", act.Duration, act)
			sum += act.Duration
			if sum >= total*9/10 {
				break
			}
		}
		if total > sum {
			fmt.Fprintf(os.Stderr, "%s\tall others\n", total-sum)
		}
	}

	return exitcode
}

// load loads the initial packages. Returns only top-level loading
// errors. Does not consider errors in packages.
func load(patterns []string, allSyntax bool) ([]*packages.Package, error) {
	mode := packages.LoadSyntax
	if allSyntax {
		mode = packages.LoadAllSyntax
	}
	mode |= packages.NeedModule
	conf := packages.Config{
		Mode:  mode,
		Tests: IncludeTests,
	}
	initial, err := packages.Load(&conf, patterns...)
	if err == nil && len(initial) == 0 {
		err = fmt.Errorf("%s matched no packages", strings.Join(patterns, " "))
	}
	return initial, err
}

// applyFixes applies suggested fixes associated with diagnostics
// reported by the specified actions. It verifies that edits do not
// conflict, even through file-system level aliases such as symbolic
// links, and then edits the files.
func applyFixes(actions []*checker.Action) error {
	// Visit all of the actions and accumulate the suggested edits.
	paths := make(map[robustio.FileID]string)
	editsByAction := make(map[robustio.FileID]map[*checker.Action][]diff.Edit)
	for _, act := range actions {
		editsForTokenFile := make(map[*token.File][]diff.Edit)
		for _, diag := range act.Diagnostics {
			for _, sf := range diag.SuggestedFixes {
				for _, edit := range sf.TextEdits {
					// Validate the edit.
					// Any error here indicates a bug in the analyzer.
					start, end := edit.Pos, edit.End
					file := act.Package.Fset.File(start)
					if file == nil {
						return fmt.Errorf("analysis %q suggests invalid fix: missing file info for pos (%v)",
							act.Analyzer.Name, edit.Pos)
					}
					if !end.IsValid() {
						end = start
					}
					if start > end {
						return fmt.Errorf("analysis %q suggests invalid fix: pos (%v) > end (%v)",
							act.Analyzer.Name, edit.Pos, edit.End)
					}
					if eof := token.Pos(file.Base() + file.Size()); end > eof {
						return fmt.Errorf("analysis %q suggests invalid fix: end (%v) past end of file (%v)",
							act.Analyzer.Name, edit.End, eof)
					}
					edit := diff.Edit{
						Start: file.Offset(start),
						End:   file.Offset(end),
						New:   string(edit.NewText),
					}
					editsForTokenFile[file] = append(editsForTokenFile[file], edit)
				}
			}
		}

		for f, edits := range editsForTokenFile {
			id, _, err := robustio.GetFileID(f.Name())
			if err != nil {
				return err
			}
			if _, hasId := paths[id]; !hasId {
				paths[id] = f.Name()
				editsByAction[id] = make(map[*checker.Action][]diff.Edit)
			}
			editsByAction[id][act] = edits
		}
	}

	// Validate and group the edits to each actual file.
	editsByPath := make(map[string][]diff.Edit)
	for id, actToEdits := range editsByAction {
		path := paths[id]
		actions := make([]*checker.Action, 0, len(actToEdits))
		for act := range actToEdits {
			actions = append(actions, act)
		}

		// Does any action create conflicting edits?
		for _, act := range actions {
			edits := actToEdits[act]
			if _, invalid := validateEdits(edits); invalid > 0 {
				name, x, y := act.Analyzer.Name, edits[invalid-1], edits[invalid]
				return diff3Conflict(path, name, name, []diff.Edit{x}, []diff.Edit{y})
			}
		}

		// Does any pair of different actions create edits that conflict?
		for j := range actions {
			for k := range actions[:j] {
				x, y := actions[j], actions[k]
				if x.Analyzer.Name > y.Analyzer.Name {
					x, y = y, x
				}
				xedits, yedits := actToEdits[x], actToEdits[y]
				combined := append(xedits, yedits...)
				if _, invalid := validateEdits(combined); invalid > 0 {
					// TODO: consider applying each action's consistent list of edits entirely,
					// and then using a three-way merge (such as GNU diff3) on the resulting
					// files to report more precisely the parts that actually conflict.
					return diff3Conflict(path, x.Analyzer.Name, y.Analyzer.Name, xedits, yedits)
				}
			}
		}

		var edits []diff.Edit
		for act := range actToEdits {
			edits = append(edits, actToEdits[act]...)
		}
		editsByPath[path], _ = validateEdits(edits) // remove duplicates. already validated.
	}

	// Now we've got a set of valid edits for each file. Apply them.
	// TODO(adonovan): don't abort the operation partway just because one file fails.
	for path, edits := range editsByPath {
		// TODO(adonovan): this should really work on the same
		// gulp from the file system that fed the analyzer (see #62292).
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		out, err := diff.ApplyBytes(contents, edits)
		if err != nil {
			return err
		}

		// Try to format the file.
		if formatted, err := format.Source(out); err == nil {
			out = formatted
		}

		if err := os.WriteFile(path, out, 0644); err != nil {
			return err
		}
	}
	return nil
}

// validateEdits returns a list of edits that is sorted and
// contains no duplicate edits. Returns the index of some
// overlapping adjacent edits if there is one and <0 if the
// edits are valid.
func validateEdits(edits []diff.Edit) ([]diff.Edit, int) {
	if len(edits) == 0 {
		return nil, -1
	}
	equivalent := func(x, y diff.Edit) bool {
		return x.Start == y.Start && x.End == y.End && x.New == y.New
	}
	diff.SortEdits(edits)
	unique := []diff.Edit{edits[0]}
	invalid := -1
	for i := 1; i < len(edits); i++ {
		prev, cur := edits[i-1], edits[i]
		// We skip over equivalent edits without considering them
		// an error. This handles identical edits coming from the
		// multiple ways of loading a package into a
		// *go/packages.Packages for testing, e.g. packages "p" and "p [p.test]".
		if !equivalent(prev, cur) {
			unique = append(unique, cur)
			if prev.End > cur.Start {
				invalid = i
			}
		}
	}
	return unique, invalid
}

// diff3Conflict returns an error describing two conflicting sets of
// edits on a file at path.
func diff3Conflict(path string, xlabel, ylabel string, xedits, yedits []diff.Edit) error {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	oldlabel, old := "base", string(contents)

	xdiff, err := diff.ToUnified(oldlabel, xlabel, old, xedits, diff.DefaultContextLines)
	if err != nil {
		return err
	}
	ydiff, err := diff.ToUnified(oldlabel, ylabel, old, yedits, diff.DefaultContextLines)
	if err != nil {
		return err
	}

	return fmt.Errorf("conflicting edits from %s and %s on %s\nfirst edits:\n%s\nsecond edits:\n%s",
		xlabel, ylabel, path, xdiff, ydiff)
}

// needFacts reports whether any analysis required by the specified set
// needs facts.  If so, we must load the entire program from source.
func needFacts(analyzers []*analysis.Analyzer) bool {
	seen := make(map[*analysis.Analyzer]bool)
	var q []*analysis.Analyzer // for BFS
	q = append(q, analyzers...)
	for len(q) > 0 {
		a := q[0]
		q = q[1:]
		if !seen[a] {
			seen[a] = true
			if len(a.FactTypes) > 0 {
				return true
			}
			q = append(q, a.Requires...)
		}
	}
	return false
}

func dbg(b byte) bool { return strings.IndexByte(Debug, b) >= 0 }
