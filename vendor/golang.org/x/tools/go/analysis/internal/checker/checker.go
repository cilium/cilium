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
	"io"
	"maps"

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
	"golang.org/x/tools/go/analysis/internal"
	"golang.org/x/tools/go/analysis/internal/analysisflags"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/internal/analysisinternal"
	"golang.org/x/tools/internal/diff"
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

	// Fix determines whether to apply (!Diff) or display (Diff) all suggested fixes.
	Fix bool

	// Diff causes the file updates to be displayed, but not applied.
	// This flag has no effect unless Fix is true.
	Diff bool
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
	flag.BoolVar(&Diff, "diff", false, "with -fix, don't update the files, but print a unified diff")
}

// Run loads the packages specified by args using go/packages,
// then applies the specified analyzers to them.
// Analysis flags must already have been set.
// Analyzers must be valid according to [analysis.Validate].
// It provides most of the logic for the main functions of both the
// singlechecker and the multi-analysis commands.
// It returns the appropriate exit code.
//
// TODO(adonovan): tests should not call this function directly;
// fiddling with global variables (flags) is error-prone and hostile
// to parallelism. Instead, use unit tests of the actual units (e.g.
// checker.Analyze) and integration tests (e.g. TestScript) of whole
// executables.
func Run(args []string, analyzers []*analysis.Analyzer) (exitcode int) {
	// Instead of returning a code directly,
	// call this function to monotonically increase the exit code.
	// This allows us to keep going in the face of some errors
	// without having to remember what code to return.
	//
	// TODO(adonovan): interpreting exit codes is like reading tea-leaves.
	// Insted of wasting effort trying to encode a multidimensional result
	// into 7 bits we should just emit structured JSON output, and
	// an exit code of 0 or 1 for success or failure.
	exitAtLeast := func(code int) {
		exitcode = max(code, exitcode)
	}

	// When analysisflags is linked in (for {single,multi}checker),
	// then the -v flag is registered for complex legacy reasons
	// related to cmd/vet CLI.
	// Treat it as an undocumented alias for -debug=v.
	if v := flag.CommandLine.Lookup("v"); v != nil &&
		v.Value.(flag.Getter).Get() == true &&
		!strings.Contains(Debug, "v") {
		Debug += "v"
	}

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
		exitAtLeast(1)
		return
	}

	// Print package and module errors regardless of RunDespiteErrors.
	// Do not exit if there are errors, yet.
	if n := packages.PrintErrors(initial); n > 0 {
		exitAtLeast(1)
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
		exitAtLeast(1)
		return
	}

	// Don't print the diagnostics,
	// but apply all fixes from the root actions.
	if Fix {
		if err := applyFixes(graph.Roots, Diff); err != nil {
			// Fail when applying fixes failed.
			log.Print(err)
			exitAtLeast(1)
			return
		}
		// Don't proceed to print text/JSON,
		// and don't report an error
		// just because there were diagnostics.
		return
	}

	// Print the results. If !RunDespiteErrors and there
	// are errors in the packages, this will have 0 exit
	// code. Otherwise, we prefer to return exit code
	// indicating diagnostics.
	exitAtLeast(printDiagnostics(graph))

	return
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
		Mode: mode,
		// Ensure that child process inherits correct alias of PWD.
		// (See discussion at Dir field of [exec.Command].)
		// However, this currently breaks some tests.
		// TODO(adonovan): Investigate.
		//
		// Dir:   os.Getenv("PWD"),
		Tests: IncludeTests,
	}
	initial, err := packages.Load(&conf, patterns...)
	if err == nil && len(initial) == 0 {
		err = fmt.Errorf("%s matched no packages", strings.Join(patterns, " "))
	}
	return initial, err
}

// applyFixes attempts to apply the first suggested fix associated
// with each diagnostic reported by the specified actions.
// All fixes must have been validated by [analysisinternal.ValidateFixes].
//
// Each fix is treated as an independent change; fixes are merged in
// an arbitrary deterministic order as if by a three-way diff tool
// such as the UNIX diff3 command or 'git merge'. Any fix that cannot be
// cleanly merged is discarded, in which case the final summary tells
// the user to re-run the tool.
// TODO(adonovan): make the checker tool re-run the analysis itself.
//
// When the same file is analyzed as a member of both a primary
// package "p" and a test-augmented package "p [p.test]", there may be
// duplicate diagnostics and fixes. One set of fixes will be applied
// and the other will be discarded; but re-running the tool may then
// show zero fixes, which may cause the confused user to wonder what
// happened to the other ones.
// TODO(adonovan): consider pre-filtering completely identical fixes.
//
// A common reason for overlapping fixes is duplicate additions of the
// same import. The merge algorithm may often cleanly resolve such
// fixes, coalescing identical edits, but the merge may sometimes be
// confused by nearby changes.
//
// Even when merging succeeds, there is no guarantee that the
// composition of the two fixes is semantically correct. Coalescing
// identical edits is appropriate for imports, but not for, say,
// increments to a counter variable; the correct resolution in that
// case might be to increment it twice. Or consider two fixes that
// each delete the penultimate reference to an import or local
// variable: each fix is sound individually, and they may be textually
// distant from each other, but when both are applied, the program is
// no longer valid because it has an unreferenced import or local
// variable.
// TODO(adonovan): investigate replacing the final "gofmt" step with a
// formatter that applies the unused-import deletion logic of
// "goimports".
//
// Merging depends on both the order of fixes and they order of edits
// within them. For example, if three fixes add import "a" twice and
// import "b" once, the two imports of "a" may be combined if they
// appear in order [a, a, b], or not if they appear as [a, b, a].
// TODO(adonovan): investigate an algebraic approach to imports;
// that is, for fixes to Go source files, convert changes within the
// import(...) portion of the file into semantic edits, compose those
// edits algebraically, then convert the result back to edits.
//
// applyFixes returns success if all fixes are valid, could be cleanly
// merged, and the corresponding files were successfully updated.
//
// If showDiff, instead of updating the files it display the final
// patch composed of all the cleanly merged fixes.
//
// TODO(adonovan): handle file-system level aliases such as symbolic
// links using robustio.FileID.
func applyFixes(actions []*checker.Action, showDiff bool) error {

	// Select fixes to apply.
	//
	// If there are several for a given Diagnostic, choose the first.
	// Preserve the order of iteration, for determinism.
	type fixact struct {
		fix *analysis.SuggestedFix
		act *checker.Action
	}
	var fixes []*fixact
	for _, act := range actions {
		for _, diag := range act.Diagnostics {
			for i := range diag.SuggestedFixes {
				fix := &diag.SuggestedFixes[i]
				if i == 0 {
					fixes = append(fixes, &fixact{fix, act})
				} else {
					// TODO(adonovan): abstract the logger.
					log.Printf("%s: ignoring alternative fix %q", act, fix.Message)
				}
			}
		}
	}

	// Read file content on demand, from the virtual
	// file system that fed the analyzer (see #62292).
	//
	// This cache assumes that all successful reads for the same
	// file name return the same content.
	// (It is tempting to group fixes by package and do the
	// merge/apply/format steps one package at a time, but
	// packages are not disjoint, due to test variants, so this
	// would not really address the issue.)
	baselineContent := make(map[string][]byte)
	getBaseline := func(readFile analysisinternal.ReadFileFunc, filename string) ([]byte, error) {
		content, ok := baselineContent[filename]
		if !ok {
			var err error
			content, err = readFile(filename)
			if err != nil {
				return nil, err
			}
			baselineContent[filename] = content
		}
		return content, nil
	}

	// Apply each fix, updating the current state
	// only if the entire fix can be cleanly merged.
	accumulatedEdits := make(map[string][]diff.Edit)
	goodFixes := 0
fixloop:
	for _, fixact := range fixes {
		readFile := internal.Pass(fixact.act).ReadFile

		// Convert analysis.TextEdits to diff.Edits, grouped by file.
		// Precondition: a prior call to validateFix succeeded.
		fileEdits := make(map[string][]diff.Edit)
		fset := fixact.act.Package.Fset
		for _, edit := range fixact.fix.TextEdits {
			file := fset.File(edit.Pos)

			baseline, err := getBaseline(readFile, file.Name())
			if err != nil {
				log.Printf("skipping fix to file %s: %v", file.Name(), err)
				continue fixloop
			}

			// We choose to treat size mismatch as a serious error,
			// as it indicates a concurrent write to at least one file,
			// and possibly others (consider a git checkout, for example).
			if file.Size() != len(baseline) {
				return fmt.Errorf("concurrent file modification detected in file %s (size changed from %d -> %d bytes); aborting fix",
					file.Name(), file.Size(), len(baseline))
			}

			fileEdits[file.Name()] = append(fileEdits[file.Name()], diff.Edit{
				Start: file.Offset(edit.Pos),
				End:   file.Offset(edit.End),
				New:   string(edit.NewText),
			})
		}

		// Apply each set of edits by merging atop
		// the previous accumulated state.
		after := make(map[string][]diff.Edit)
		for file, edits := range fileEdits {
			if prev := accumulatedEdits[file]; len(prev) > 0 {
				merged, ok := diff.Merge(prev, edits)
				if !ok {
					// debugging
					if false {
						log.Printf("%s: fix %s conflicts", fixact.act, fixact.fix.Message)
					}
					continue fixloop // conflict
				}
				edits = merged
			}
			after[file] = edits
		}

		// The entire fix applied cleanly; commit it.
		goodFixes++
		maps.Copy(accumulatedEdits, after)
		// debugging
		if false {
			log.Printf("%s: fix %s applied", fixact.act, fixact.fix.Message)
		}
	}
	badFixes := len(fixes) - goodFixes

	// Show diff or update files to final state.
	var files []string
	for file := range accumulatedEdits {
		files = append(files, file)
	}
	sort.Strings(files) // for deterministic -diff
	var filesUpdated, totalFiles int
	for _, file := range files {
		edits := accumulatedEdits[file]
		if len(edits) == 0 {
			continue // the diffs annihilated (a miracle?)
		}

		// Apply accumulated fixes.
		baseline := baselineContent[file] // (cache hit)
		final, err := diff.ApplyBytes(baseline, edits)
		if err != nil {
			log.Fatalf("internal error in diff.ApplyBytes: %v", err)
		}

		// Attempt to format each file.
		if formatted, err := format.Source(final); err == nil {
			final = formatted
		}

		if showDiff {
			// Since we formatted the file, we need to recompute the diff.
			unified := diff.Unified(file+" (old)", file+" (new)", string(baseline), string(final))
			// TODO(adonovan): abstract the I/O.
			os.Stdout.WriteString(unified)

		} else {
			// write
			totalFiles++
			// TODO(adonovan): abstract the I/O.
			if err := os.WriteFile(file, final, 0644); err != nil {
				log.Println(err)
				continue
			}
			filesUpdated++
		}
	}

	// TODO(adonovan): consider returning a structured result that
	// maps each SuggestedFix to its status:
	// - invalid
	// - secondary, not selected
	// - applied
	// - had conflicts.
	// and a mapping from each affected file to:
	// - its final/original content pair, and
	// - whether formatting was successful.
	// Then file writes and the UI can be applied by the caller
	// in whatever form they like.

	// If victory was incomplete, report an error that indicates partial progress.
	//
	// badFixes > 0 indicates that we decided not to attempt some
	// fixes due to conflicts or failure to read the source; still
	// it's a relatively benign situation since the user can
	// re-run the tool, and we may still make progress.
	//
	// filesUpdated < totalFiles indicates that some file updates
	// failed. This should be rare, but is a serious error as it
	// may apply half a fix, or leave the files in a bad state.
	//
	// These numbers are potentially misleading:
	// The denominator includes duplicate conflicting fixes due to
	// common files in packages "p" and "p [p.test]", which may
	// have been fixed fixed and won't appear in the re-run.
	// TODO(adonovan): eliminate identical fixes as an initial
	// filtering step.
	//
	// TODO(adonovan): should we log that n files were updated in case of total victory?
	if badFixes > 0 || filesUpdated < totalFiles {
		if showDiff {
			return fmt.Errorf("%d of %d fixes skipped (e.g. due to conflicts)", badFixes, len(fixes))
		} else {
			return fmt.Errorf("applied %d of %d fixes; %d files updated. (Re-run the command to apply more.)",
				goodFixes, len(fixes), filesUpdated)
		}
	}

	if dbg('v') {
		log.Printf("applied %d fixes, updated %d files", len(fixes), filesUpdated)
	}

	return nil
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
