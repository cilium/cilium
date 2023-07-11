// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package main creates the main function to run all analyzers in this module.
package main

import (
	"github.com/cilium/linters/ioreadall"
	"github.com/cilium/linters/timeafter"

	"golang.org/x/tools/go/analysis/multichecker"
)

func main() {
	multichecker.Main(timeafter.Analyzer, ioreadall.Analyzer)
}
