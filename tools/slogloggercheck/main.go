// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

const (
	exitOK   = 0
	exitFail = 1

	// The required comment that justifies DefaultSlogLogger usage
	requiredComment = "slogloggercheck:"
)

func main() {
	flag.Parse()

	var failed bool
	args := flag.Args()

	// If no arguments are provided, check current directory
	if len(args) == 0 {
		args = []string{"."}
	}

	// Check each path provided as argument
	for _, arg := range args {
		// Handle paths with trailing /...
		if strings.HasSuffix(arg, "/...") {
			arg = strings.TrimSuffix(arg, "/...")
		}

		if err := filepath.Walk(arg, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip errors
			}

			// Skip vendor directory
			if info.IsDir() && path != arg && (info.Name() == "vendor" || strings.Contains(path, "/vendor/")) {
				return filepath.SkipDir
			}

			if info.IsDir() {
				return nil
			}

			if !strings.HasSuffix(path, ".go") {
				return nil
			}

			if !checkFile(path) {
				failed = true
			}

			return nil
		}); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to walk directory %s: %v\n", arg, err)
			os.Exit(exitFail)
		}
	}

	if failed {
		os.Exit(exitFail)
	}

	os.Exit(exitOK)
}

// checkFile parses and checks a single file for improper DefaultSlogLogger usage.
// It returns false if the file contains violations.
func checkFile(path string) bool {
	// Skip checking the file that defines DefaultSlogLogger
	if strings.HasSuffix(path, "pkg/logging/slog.go") ||
		strings.HasSuffix(path, "pkg/logging/logging_test.go") {
		return true
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse file %s: %v\n", path, err)
		return false
	}

	v := &visitor{
		fileSet:  fset,
		fileName: path,
		found:    false,
	}

	ast.Walk(v, f)

	return !v.found
}

// visitor implements the ast.Visitor interface to find DefaultSlogLogger usages.
type visitor struct {
	fileSet  *token.FileSet
	fileName string
	found    bool
}

// Visit checks nodes for DefaultSlogLogger usage without justification.
func (v *visitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}

	// Look for selector expressions (package.identifier)
	selectorExpr, ok := node.(*ast.SelectorExpr)
	if !ok {
		return v
	}

	// Check if it's a reference to logging.DefaultSlogLogger
	if ident, ok := selectorExpr.X.(*ast.Ident); ok {
		if ident.Name == "logging" && selectorExpr.Sel.Name == "DefaultSlogLogger" {
			// Check if there's a justification comment nearby
			pos := v.fileSet.Position(node.Pos())
			if !hasJustificationComment(v.fileSet, node) {
				fmt.Printf("%s:%d: direct use of logging.DefaultSlogLogger without justification comment\n",
					v.fileName, pos.Line)
				fmt.Printf("  Add a comment with '%s <reason>' to justify this usage\n", requiredComment)
				v.found = true
			}
		}
	}

	return v
}

// hasJustificationComment checks if there's a comment containing the required text
// on the same line or in the line above the node.
func hasJustificationComment(fset *token.FileSet, node ast.Node) bool {
	// Get position info
	pos := fset.Position(node.Pos())
	file := pos.Filename
	line := pos.Line

	// Read the file content
	content, err := os.ReadFile(file)
	if err != nil {
		return false
	}

	lines := strings.Split(string(content), "\n")

	// Check the line with the node and the line above
	for l := line - 1; l <= line; l++ {
		if l <= 0 || l > len(lines) {
			continue
		}

		if strings.Contains(lines[l-1], requiredComment) {
			return true
		}
	}

	return false
}
