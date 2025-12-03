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
	"io"

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
}

// Run loads the packages specified by args using go/packages,
// then applies the specified analyzers to them.
// Analysis flags must already have been set.
// Analyzers must be valid according to [analysis.Validate].
// It provides most of the logic for the main functions of both the
// singlechecker and the multi-analysis commands.
// It returns the appropriate exit code.
//
// TODO(adonovan): tests should not call this function directly.
// Fiddling with global variables (flags such as [analysisflags.Fix])
// is error-prone and hostile to parallelism. Instead, use unit tests
// of the actual units (e.g. checker.Analyze) and integration tests
// (e.g. TestScript) of whole executables.
func Run(args []string, analyzers []*analysis.Analyzer) (exitcode int) {
	// Instead of returning a code directly,
	// call this function to monotonically increase the exit code.
	// This allows us to keep going in the face of some errors
	// without having to remember what code to return.
	//
	// TODO(adonovan): interpreting exit codes is like reading tea-leaves.
	// Instead of wasting effort trying to encode a multidimensional result
	// into 7 bits we should just emit structured JSON output, and
	// an exit code of 0 or 1 for success or failure.
	exitAtLeast := func(code int) {
		exitcode = max(code, exitcode)
	}

	// Since analysisflags is linked in (for {single,multi}checker),
	// the -v flag is registered for complex legacy reasons
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
	if analysisflags.Fix {
		fixActions := make([]analysisflags.FixAction, len(graph.Roots))
		for i, act := range graph.Roots {
			if pass := internal.ActionPass(act); pass != nil {
				fixActions[i] = analysisflags.FixAction{
					Name:         act.String(),
					FileSet:      act.Package.Fset,
					ReadFileFunc: pass.ReadFile,
					Diagnostics:  act.Diagnostics,
				}
			}
		}
		if err := analysisflags.ApplyFixes(fixActions, dbg('v')); err != nil {
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
	// Keep consistent with analogous logic in
	// processResults in ../../unitchecker/unitchecker.go.

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
		for act := range graph.All() {
			if act.Err != nil {
				numErrors++
			} else if act.IsRoot {
				rootDiags += len(act.Diagnostics)
			}
		}

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
		for act := range graph.All() {
			list = append(list, act)
			total += act.Duration
		}

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
