// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package singlechecker defines the main function for an analysis
// driver with only a single analyzer.
//
// This package makes it convenient for an analysis package to also
// provide a standalone tool that runs just that one analyzer.
//
// For example, if example.com/findbadness is an analysis package,
// then adding this main.go file to its directory makes it easy to
// build a standalone tool:
//
//	//go:build ignore
//
//	// The findbadness command runs an analysis.
//	package main
//
//	import (
//		"example.com/findbadness"
//		"golang.org/x/tools/go/analysis/singlechecker"
//	)
//
//	func main() { singlechecker.Main(findbadness.Analyzer) }
//
// It can be built and run (in whole-program mode) using these commands:
//
//	$ go build -o findbadness example.com/findbadness/main.go
//	$ findbadness [packages...]
//
// or run in package-at-a-time mode using this command:
//
//	$ go vet -vettool=./findbadness [packages...]
//
// For more detail, see the documentation for
// [golang.org/x/tools/go/analysis/multichecker]; the only significant
// difference between them is that the command-line interface of
// singlechecker is tailored to a single analyzer.
package singlechecker

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/internal/analysisflags"
	"golang.org/x/tools/go/analysis/internal/checker"
	"golang.org/x/tools/go/analysis/unitchecker"
)

// Main is the main function for a checker command for a single analysis.
// It parses the command line, analyzes all the packages, prints any
// diagnostics, then terminates the process.
func Main(a *analysis.Analyzer) {
	log.SetFlags(0)
	log.SetPrefix(a.Name + ": ")

	analyzers := []*analysis.Analyzer{a}

	if err := analysis.Validate(analyzers); err != nil {
		log.Fatal(err)
	}

	checker.RegisterFlags()

	flag.Usage = func() {
		paras := strings.Split(a.Doc, "\n\n")
		fmt.Fprintf(os.Stderr, "%s: %s\n\n", a.Name, paras[0])
		fmt.Fprintf(os.Stderr, "Usage: %s [-flag] [package]\n\n", a.Name)
		if len(paras) > 1 {
			fmt.Fprintln(os.Stderr, strings.Join(paras[1:], "\n\n"))
		}
		fmt.Fprintln(os.Stderr, "\nFlags:")
		flag.PrintDefaults()
	}

	analyzers = analysisflags.Parse(analyzers, false)

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if len(args) == 1 && strings.HasSuffix(args[0], ".cfg") {
		unitchecker.Run(args[0], analyzers)
		panic("unreachable")
	}

	os.Exit(checker.Run(args, analyzers))
}
