// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	cwd, _ := os.Getwd()
	testdata := filepath.Join(cwd, "testdata")
	analysistest.Run(t, testdata, Analyzer)
}
