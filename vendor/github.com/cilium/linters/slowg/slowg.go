// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package slowg

import (
	"errors"
	"go/ast"
	"go/types"

	_ "golang.org/x/exp/slog" // require the exp module for the unit tests
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/types/typeutil"

	"github.com/cilium/linters/analysisutil"
)

// Analyzer implements an analysis function that checks for inappropriate use
// of Logger.With.
var Analyzer = &analysis.Analyzer{
	Name:     "slowg",
	Doc:      "check for inappropriate use of Logger.With()",
	URL:      "https://github.com/cilium/linters",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	if !analysisutil.ImportsPackage(pass.Pkg, "log/slog") &&
		!analysisutil.ImportsPackage(pass.Pkg, "golang.org/x/exp/slog") {
		return nil, nil // doesn't directly import slog package
	}

	inspect, ok := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	if !ok {
		return nil, errors.New("require analyzer of type *inspector.Inspector")
	}
	nodeFilter := []ast.Node{
		(*ast.SelectorExpr)(nil),
	}
	inspect.Preorder(nodeFilter, func(node ast.Node) {
		sel, ok := node.(*ast.SelectorExpr)
		if !ok {
			return
		}

		if sel.Sel == nil {
			return
		}
		call, ok := sel.X.(*ast.CallExpr)
		if !ok {
			return
		}
		fn := typeutil.StaticCallee(pass.TypesInfo, call)
		if fn == nil {
			// not a static call
			return
		}
		if !isSlogPkg(fn) {
			// not the log/slog or x/exp/slog package
			return
		}
		if recvName(fn) != "Logger" {
			// not a receiver of the Logger struct
			return
		}
		switch fn.Name() {
		case "With", "WithGroup":
		default:
			// not one of the call we need to care about
			return
		}
		meth := sel.Sel.Name
		if !isLogMethod(meth) {
			// not a logging method (e.g. Info, DebugCtx, ...)
			return
		}
		pass.ReportRangef(call, "call to %s on a newly instantiated Logger", meth)
	})
	return nil, nil
}

func isSlogPkg(fn *types.Func) bool {
	switch fn.Pkg().Path() {
	case "log/slog":
		return true
	case "golang.org/x/exp/slog":
		return true
	}
	return false
}

func isLogMethod(s string) bool {
	switch s {
	case "Log", "LogAttrs",
		"Debug", "Info", "Warn", "Error",
		"DebugCtx", "InfoCtx", "WarnCtx", "ErrorCtx", // old method names, still used in x/exp/slog
		"DebugContext", "InfoContext", "WarnContext", "ErrorContext":
		return true
	}
	return false
}

func recvName(fn *types.Func) string {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return ""
	}
	recv := sig.Recv()
	if recv != nil {
		t := recv.Type()
		if pt, ok := t.(*types.Pointer); ok {
			t = pt.Elem()
		}
		if nt, ok := t.(*types.Named); ok {
			return nt.Obj().Name()
		}
	}
	return ""
}
