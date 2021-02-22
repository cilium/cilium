package astutil

import (
	"go/ast"
	"go/token"
	"strings"
)

func IsIdent(expr ast.Expr, ident string) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == ident
}

// isBlank returns whether id is the blank identifier "_".
// If id == nil, the answer is false.
func IsBlank(id ast.Expr) bool {
	ident, _ := id.(*ast.Ident)
	return ident != nil && ident.Name == "_"
}

func IsIntLiteral(expr ast.Expr, literal string) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == literal
}

// Deprecated: use IsIntLiteral instead
func IsZero(expr ast.Expr) bool {
	return IsIntLiteral(expr, "0")
}

func Preamble(f *ast.File) string {
	cutoff := f.Package
	if f.Doc != nil {
		cutoff = f.Doc.Pos()
	}
	var out []string
	for _, cmt := range f.Comments {
		if cmt.Pos() >= cutoff {
			break
		}
		out = append(out, cmt.Text())
	}
	return strings.Join(out, "\n")
}

func GroupSpecs(fset *token.FileSet, specs []ast.Spec) [][]ast.Spec {
	if len(specs) == 0 {
		return nil
	}
	groups := make([][]ast.Spec, 1)
	groups[0] = append(groups[0], specs[0])

	for _, spec := range specs[1:] {
		g := groups[len(groups)-1]
		if fset.PositionFor(spec.Pos(), false).Line-1 !=
			fset.PositionFor(g[len(g)-1].End(), false).Line {

			groups = append(groups, nil)
		}

		groups[len(groups)-1] = append(groups[len(groups)-1], spec)
	}

	return groups
}
