// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package multichecker defines the main function for an analysis driver
// with several analyzers. This package makes it easy for anyone to build
// an analysis tool containing just the analyzers they need.
//
// Assuming my.exe is an executable that simply calls
// [multichecker.Main], passing it a list of analyzers, you can
// execute it using this command:
//
//	$ my.exe [flags] [packages...]
//
// The resulting command is a whole-program driver: given a list of
// package patterns, such as "./...", it loads the packages using
// [golang.org/x/tools/go/packages] and analyzes them all in a single
// process. See the Drivers section of the
// [golang.org/x/tools/go/analysis] package documentation for more
// detail.
//
// For convenience, the command also detects when it is invoked in
// package-at-a-time mode by a build system, as in
//
//	$ go vet -vettool=/path/to/my.exe [packages...]
//
// in which case it analyzes only the single compilation unit that the
// build system describes to it; see
// [golang.org/x/tools/go/analysis/unitchecker].
package multichecker

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/internal/analysisflags"
	"golang.org/x/tools/go/analysis/internal/checker"
	"golang.org/x/tools/go/analysis/unitchecker"
)

// Main is the main function for a checker command that runs the
// specified analyzers. It parses the command line, analyzes all the
// packages, prints any diagnostics, then terminates the process.
func Main(analyzers ...*analysis.Analyzer) {
	progname := filepath.Base(os.Args[0])
	log.SetFlags(0)
	log.SetPrefix(progname + ": ") // e.g. "vet: "

	if err := analysis.Validate(analyzers); err != nil {
		log.Fatal(err)
	}

	checker.RegisterFlags()

	analyzers = analysisflags.Parse(analyzers, true)

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, `%[1]s is a tool for static analysis of Go programs.

Usage: %[1]s [-flag] [package]

Run '%[1]s help' for more detail,
 or '%[1]s help name' for details and flags of a specific analyzer.
`, progname)
		os.Exit(1)
	}

	if args[0] == "help" {
		analysisflags.Help(progname, analyzers, args[1:])
		os.Exit(0)
	}

	if len(args) == 1 && strings.HasSuffix(args[0], ".cfg") {
		unitchecker.Run(args[0], analyzers)
		panic("unreachable")
	}

	os.Exit(checker.Run(args, analyzers))
}
