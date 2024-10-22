// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package timeafter

import (
	"errors"
	"fmt"
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const (
	timeAfterPkg  = "time"
	timeAfterFunc = "After"
)

// Analyzer implements an analysis function that checks for the use of
// time.After in loops.
var Analyzer = &analysis.Analyzer{
	Name:     "timeafter",
	Doc:      `check for "time.After" instances in loops`,
	URL:      "https://github.com/cilium/linters",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

var ignoreArg string

func init() {
	Analyzer.Flags.StringVar(&ignoreArg, "ignore", "", `list of packages to ignore ("inctimer,time")`)
}

type visitor func(ast.Node) bool

func (v visitor) Visit(node ast.Node) ast.Visitor {
	if v(node) {
		return v
	}
	return nil
}

func run(pass *analysis.Pass) (interface{}, error) {
	inspct, ok := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	if !ok {
		return nil, errors.New("analyzer is not type *inspector.Inspector")
	}

	ignoreMap := make(map[string]struct{})
	for _, ign := range strings.Split(ignoreArg, ",") {
		ignoreMap[strings.TrimSpace(ign)] = struct{}{}
	}

	var (
		pkgAliases []string
		ignore     = false
		nodeFilter = []ast.Node{
			(*ast.ForStmt)(nil),
			(*ast.RangeStmt)(nil),
			(*ast.File)(nil),
			(*ast.ImportSpec)(nil),
		}
	)
	inspct.Preorder(nodeFilter, func(n ast.Node) {
		switch stmt := n.(type) {
		case *ast.File:
			_, ignore = ignoreMap[stmt.Name.Name]
			pkgAliases = []string{timeAfterPkg}
		case *ast.ImportSpec:
			if ignore {
				return
			}
			// Collect aliases.
			pkg := stmt.Path.Value
			if pkg == fmt.Sprintf("%q", timeAfterPkg) {
				if stmt.Name != nil {
					pkgAliases = append(pkgAliases, stmt.Name.Name)
				}
			}
		case *ast.ForStmt:
			if ignore {
				return
			}
			checkForStmt(pass, stmt.Body, pkgAliases)
		case *ast.RangeStmt:
			if ignore {
				return
			}
			checkForStmt(pass, stmt.Body, pkgAliases)
		}
	})
	return nil, nil
}

func checkForStmt(pass *analysis.Pass, body *ast.BlockStmt, pkgAliases []string) {
	ast.Walk(visitor(func(node ast.Node) bool {
		switch expr := node.(type) {
		case *ast.CallExpr:
			for _, pkg := range pkgAliases {
				if isPkgDot(expr.Fun, pkg, timeAfterFunc) {
					pass.Reportf(node.Pos(), "use of %s.After in a for loop is prohibited, use inctimer instead", pkg)
				}
			}
		}
		return true
	}), body)
}

func isPkgDot(expr ast.Expr, pkg, name string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	res := ok && isIdent(sel.X, pkg) && isIdent(sel.Sel, name)
	return res
}

func isIdent(expr ast.Expr, ident string) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == ident
}
