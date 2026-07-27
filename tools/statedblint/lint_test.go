// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

var repoRoot, _ = filepath.Abs("../../")

func TestAnalyzer(t *testing.T) {
	analyzer := NewAnalyzer()
	if err := analyzer.Flags.Set(skipInternalTestFilesFlag, "false"); err != nil {
		t.Fatal(err)
	}
	analysistest.Run(t, repoRoot, analyzer,
		"github.com/cilium/cilium/tools/statedblint/tests/basic",
		"github.com/cilium/cilium/tools/statedblint/tests/nostatedb")
}

func TestAnalyzerStrict(t *testing.T) {
	analyzer := NewAnalyzer()
	if err := analyzer.Flags.Set(skipInternalTestFilesFlag, "false"); err != nil {
		t.Fatal(err)
	}
	if err := analyzer.Flags.Set(strictChangesCloseFlag, "true"); err != nil {
		t.Fatal(err)
	}
	analysistest.Run(t, repoRoot, analyzer,
		"github.com/cilium/cilium/tools/statedblint/tests/strict")
}
