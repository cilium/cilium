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

	// The required comment that justifies String() method calls in logging functions
	stringMethodComment = "slogloggercheck-to-string:"
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
		arg = strings.TrimSuffix(arg, "/...")

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

// Visit checks nodes for DefaultSlogLogger usage without justification
// and String() method calls in logging functions.
func (v *visitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}

	// Check for DefaultSlogLogger usage
	if selectorExpr, ok := node.(*ast.SelectorExpr); ok {
		// Check if it's a reference to logging.DefaultSlogLogger
		if ident, ok := selectorExpr.X.(*ast.Ident); ok {
			if ident.Name == "logging" && selectorExpr.Sel.Name == "DefaultSlogLogger" {
				// Check if there's a justification comment nearby
				pos := v.fileSet.Position(node.Pos())
				if !hasJustificationComment(v.fileSet, node, requiredComment) {
					fmt.Printf("%s:%d: direct use of logging.DefaultSlogLogger without justification comment\n",
						v.fileName, pos.Line)
					fmt.Printf("  Add a comment with '%s <reason>' to justify this usage\n", requiredComment)
					v.found = true
				}
			}
		}
	}

	// Check for String() calls in logging functions
	if callExpr, ok := node.(*ast.CallExpr); ok {
		// Check if it's a logger method call (e.g., logger.Debug, logger.Info)
		if sel, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
			// Check if the method is a logging method (Debug, Info, Warn, Error)
			if isLoggingMethod(sel.Sel.Name) {
				// Examine arguments for String() calls
				v.checkLoggingCallArgs(sel.Sel.Name, callExpr.Args)
			}
		}
	}

	return v
}

// checkLoggingCallArgs examines the arguments of a logging call for String() method invocations
func (v *visitor) checkLoggingCallArgs(methodName string, args []ast.Expr) {
	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Look for direct String() calls in the argument
		if stringCall, isPtr := v.findStringMethodCall(arg); stringCall != nil && !isPtr {
			pos := v.fileSet.Position(stringCall.Pos())
			if !hasJustificationComment(v.fileSet, arg, stringMethodComment) {
				fmt.Printf("%s:%d: String() method call on a non-pointer in %s() logging function MUST be avoided\n",
					v.fileName, pos.Line, methodName)
				fmt.Printf("  This will cause unnecessary string conversion even when the log level is disabled\n")
				fmt.Printf("  Simply don't call the String()\n")
				fmt.Printf("  If it is impossible to remove String(), add a comment with '%s <reason>' to justify this usage\n", stringMethodComment)
				v.found = true
			}
			continue
		}

		// Special handling for key-value pairs in structured logging
		// If this is an even-indexed argument (0, 2, 4...) and there's another argument after it,
		// and the next argument contains a String() call
		if i+1 < len(args) && i%2 == 0 {
			nextArg := args[i+1]
			if stringCall, isPtr := v.findStringMethodCall(nextArg); stringCall != nil && !isPtr {
				pos := v.fileSet.Position(stringCall.Pos())
				if !hasJustificationComment(v.fileSet, nextArg, stringMethodComment) {
					// Get the key name if possible
					keyName := "value"
					if ident, ok := arg.(*ast.Ident); ok {
						keyName = ident.Name
					}

					fmt.Printf("%s:%d: String() method call on a non-pointer for key '%s' in %s() logging function MUST be avoided\n",
						v.fileName, pos.Line, keyName, methodName)
					fmt.Printf("  This will cause unnecessary string conversion even when the log level is disabled\n")
					fmt.Printf("  Simply don't call the String()\n")
					fmt.Printf("  If not possible you can justify with '%s <reason>' to justify this usage\n", stringMethodComment)
					v.found = true
				}
			}
		}
	}
}

// isLoggingMethod checks if the method name is a logging method.
func isLoggingMethod(name string) bool {
	switch name {
	case "Debug", "DebugContext", "Info", "InfoContext", "Warn", "WarnContext", "Error", "ErrorContext", "Fatal":
		return true
	default:
		return false
	}
}

// findStringMethodCall recursively checks if an expression contains a String() method call.
// It returns the CallExpr node representing the String() call and a boolean indicating if it's on a pointer type.
func (v *visitor) findStringMethodCall(expr ast.Expr) (stringCall *ast.CallExpr, isPointer bool) {
	switch e := expr.(type) {
	case *ast.CallExpr:
		// Check if it's a String() method call
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "String" && len(e.Args) == 0 {
				// Get the receiver of the String() call
				receiver := sel.X

				// Check if the receiver is a direct pointer: *x.String()
				if _, ok := receiver.(*ast.StarExpr); ok {
					return e, true
				}

				// Check if the receiver is an identifier that might be a pointer variable
				if ident, ok := receiver.(*ast.Ident); ok {
					// Check if the identifier starts with a lowercase letter (likely a local var)
					// and is a single letter (common for pointer vars like d := &s)
					if len(ident.Name) == 1 && ident.Name[0] >= 'a' && ident.Name[0] <= 'z' {
						// This is a heuristic - we assume single-letter lowercase variables
						// might be pointers, err on the side of caution
						return e, true
					}
				}

				// Check for func calls that return pointers: getPtrObj().String()
				if _, ok := receiver.(*ast.CallExpr); ok {
					// We can't determine if a function returns a pointer without type info
					// So we'll err on the side of caution and treat it as potentially a pointer
					return e, true
				}

				return e, false // Default to non-pointer for other cases
			}
		}

		// Check function arguments for String() calls
		for _, arg := range e.Args {
			if call, isPtr := v.findStringMethodCall(arg); call != nil {
				return call, isPtr
			}
		}

	case *ast.BinaryExpr:
		// Check both sides of binary expressions (like string + string)
		if call, isPtr := v.findStringMethodCall(e.X); call != nil {
			return call, isPtr
		}
		if call, isPtr := v.findStringMethodCall(e.Y); call != nil {
			return call, isPtr
		}

	case *ast.CompositeLit:
		// Check composite literals (like structs or arrays)
		for _, elt := range e.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if call, isPtr := v.findStringMethodCall(kv.Value); call != nil {
					return call, isPtr
				}
			} else if call, isPtr := v.findStringMethodCall(elt); call != nil {
				return call, isPtr
			}
		}

	// Handle other expression types that might contain a String() call
	case *ast.ParenExpr:
		return v.findStringMethodCall(e.X)

	case *ast.SelectorExpr:
		// This handles cases where the String() might be part of a chained call
		if e.Sel.Name == "String" {
			// Similar checks as above for determining if it's a pointer
			if _, ok := e.X.(*ast.StarExpr); ok {
				// This is explicitly a pointer: *x
				return nil, true
			}
		}
	}

	return nil, false
}

// hasJustificationComment checks if there's a comment containing the required text
// on the same line or in the line above the node.
func hasJustificationComment(fset *token.FileSet, node ast.Node, comment string) bool {
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

		if strings.Contains(lines[l-1], comment) {
			return true
		}
	}

	return false
}
