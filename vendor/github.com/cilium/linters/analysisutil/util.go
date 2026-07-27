// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package analysisutil defines helper functions used by more than one linters.
package analysisutil

import "go/types"

// ImportsPackage reports whether path is imported by pkg.
//
// Copied from
// golang.org/x/tools/go/analysis/passes/internal/analysisutil.Imports.
func ImportsPackage(pkg *types.Package, path string) bool {
	for _, imp := range pkg.Imports() {
		if imp.Path() == path {
			return true
		}
	}
	return false
}
