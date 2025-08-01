// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var Analyzer = &analysis.Analyzer{
	Name:     "metricslint",
	Doc:      "Checks that metrics calls use the appropriate number of parameters",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

var warnDeprecated = true

func callName(call *ast.CallExpr) string {
	if fn, ok := call.Fun.(*ast.Ident); ok {
		return fn.Name
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return ""
}

func getEllipsisRHSExpansion(expr ast.Expr) (*ast.CompositeLit, error) {
	var ident *ast.Ident

	sel, ok := expr.(*ast.SelectorExpr)
	if ok {
		ident, ok = sel.X.(*ast.Ident)
	} else {
		ident, ok = expr.(*ast.Ident)
	}
	if !ok {
		return nil, fmt.Errorf("unknown identifier")
	}

	inlineAssignment, ok := ident.Obj.Decl.(*ast.AssignStmt)
	if !ok {
		return nil, fmt.Errorf("expected assignment statement")
	}
	if len(inlineAssignment.Rhs) != 1 {
		return nil, fmt.Errorf("unexpected RHS expression length")
	}

	slice, ok := inlineAssignment.Rhs[0].(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("expected composite literal")
	}
	return slice, nil
}

func countArgs(call *ast.CallExpr) (int, error) {
	if call.Ellipsis == token.NoPos {
		// Simple path: Args are directly specified to the method.
		return len(call.Args), nil
	}
	if len(call.Args) != 1 {
		return 0, fmt.Errorf("unsupported ellipsis expression")
	}
	if warnDeprecated {
		fmt.Fprintf(os.Stderr, "metricslint: Warning: Using deprecated 'ast.Object'\n")
		warnDeprecated = false
	}

	slice, err := getEllipsisRHSExpansion(call.Args[0])
	if slice == nil {
		return 0, fmt.Errorf("unsupported varlen array: %w", err)
	}
	if _, ok := slice.Type.(*ast.ArrayType); ok {
		// Ellipsis points to a static array, so we can count the
		// number of parameters to the method following expansion.
		return len(slice.Elts), nil
	}
	if len(slice.Elts) != 1 {
		err := fmt.Errorf("expected non-zero array length")
		return 0, fmt.Errorf("unsupported nested varlen array: %w", err)
	}

	nestedKV, ok := slice.Elts[0].(*ast.KeyValueExpr)
	if !ok {
		return 0, fmt.Errorf("unsupported nested varlen array type")
	}
	nestedSlice, err := getEllipsisRHSExpansion(nestedKV.Value)
	if nestedSlice == nil {
		return 0, fmt.Errorf("unsupported nested varlen array: %w", err)
	}
	return len(nestedSlice.Elts), nil
}

func filterRelevantConstructors(node ast.Node) (object, constructor string, argCount int, err error) {
	// Look for an initializer with key-value expressions that call another
	// function to initialize the field.
	kv, ok := node.(*ast.KeyValueExpr)
	if !ok {
		return "", "", 0, fmt.Errorf("expected KeyValueExpr")
	}
	key, ok := kv.Key.(*ast.Ident)
	if !ok {
		return "", "", 0, fmt.Errorf("expected Key as Ident")
	}
	call, ok := kv.Value.(*ast.CallExpr)
	if !ok {
		return "", "", 0, fmt.Errorf("expected Value as CallExpr")
	}

	// Look for a function with at least two args, where the last arg is a
	// composite literal (such as a slice). Example:
	//
	//     metric.NewCounterVec(opts, []string{...})
	if len(call.Args) < 2 {
		return "", "", 0, fmt.Errorf("expected 2+ arguments to constructor")
	}
	lastArg, ok := call.Args[len(call.Args)-1].(*ast.CompositeLit)
	if !ok {
		return "", "", 0, fmt.Errorf("expected last arg as CompositeLit")
	}

	// Store the object and the initializer function. Assume there's just
	// one which has a composite literal as the last parameter.
	object = key.Name
	argCount = len(lastArg.Elts)
	constructor = callName(call)
	if constructor == "" {
		return "", "", 0, fmt.Errorf("unexpected CallExpr type")
	}

	if !((strings.HasPrefix(constructor, "New") ||
		strings.HasPrefix(constructor, "new")) &&
		strings.HasSuffix(constructor, "Vec")) {
		return "", "", 0, fmt.Errorf("ignoring noisy constructor name")
	}

	return object, constructor, argCount, nil
}

func filterRelevantMethods(call *ast.CallExpr) (object, method string, err error) {
	fn, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", fmt.Errorf("expected SelectorExpr")
	}

	if !strings.HasPrefix(fn.Sel.Name, "With") {
		return "", "", fmt.Errorf("ignoring noisy method name")
	}

	obj, ok := fn.X.(*ast.SelectorExpr)
	if !ok {
		return "", "", fmt.Errorf("expected function to be a method")
	}

	return obj.Sel.Name, fn.Sel.Name, nil
}

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// Collect objects that are initialized with a variable length slice
	// parameter as the last argument to a constructor. Map object name to
	// parameter count, and store the constructor name for later reference.
	objs := make(map[string]int)
	constructors := make(map[string]string)
	insp.Preorder([]ast.Node{
		(*ast.KeyValueExpr)(nil),
	}, func(node ast.Node) {
		obj, constructor, args, err := filterRelevantConstructors(node)
		if err != nil {
			// These errors are not problems, they're just AST
			// nodes that this logic does not need to traverse.
			return
		}
		if _, ok := objs[obj]; ok {
			// Right now we're narrowing the noise by applying
			// function string prefix / suffix filters in the
			// filter*() functions above; this significantly
			// reduces the noise from this check.
			pass.Reportf(node.Pos(), "metricslint bug: unexpected additional initializer '%s' for '%s'\n",
				constructor, obj)
			return
		}
		objs[obj] = args
		constructors[obj] = constructor
	})

	// Check for methods with variable length parameters that call into
	// functions linked to the initialized object above.
	insp.Preorder([]ast.Node{
		(*ast.CallExpr)(nil),
	}, func(node ast.Node) {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return
		}

		obj, method, err := filterRelevantMethods(call)
		if err != nil {
			// These errors are not problems, they're just AST
			// nodes that this logic does not need to traverse.
			return
		}
		params, ok := objs[obj]
		if !ok {
			// Constructor was not located earlier. Skip.
			return
		}

		count, err := countArgs(call)
		if err != nil {
			ast.Print(nil, call)
			pass.Reportf(node.Pos(), "metricslint bug: unable to parse AST for call '%s' on object '%s' initialized by '%s': %s",
				method, obj, constructors[obj], err)
			return
		}
		if count != params {
			pass.Reportf(node.Pos(), "metricslint: Method '%s' should have equal parameter count to call '%s' which initializes '%s'; want: %d, got: %d",
				method, constructors[obj], obj, params, count)
		}
	})

	return nil, nil
}
