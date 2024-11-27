package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

var inplace = flag.Bool("i", false, "Modify in-place")

var skipPackages = []string{
	"github.com/cilium/cilium/pkg/labels",
}

func main() {
	flag.Parse()

	// Many tools pass their command-line arguments (after any flags)
	// uninterpreted to packages.Load so that it can interpret them
	// according to the conventions of the underlying build system.
	cfg := &packages.Config{
		Mode:  packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Tests: true,
	}
	pkgs, err := packages.Load(cfg, flag.Args()...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load: %v\n", err)
		os.Exit(1)
	}
	if packages.PrintErrors(pkgs) > 0 {
		os.Exit(1)
	}

	// Print the names of the source files
	// for each package listed on the command line.
pkgsLoop:
	for _, pkg := range pkgs {
		if !strings.Contains(pkg.ID, "labelsfilter") {
			for _, prefix := range skipPackages {
				if strings.HasPrefix(pkg.ID, prefix) {
					continue pkgsLoop
				}
			}
		}
		fmt.Println(pkg.ID)
		for i, f := range pkg.Syntax {
			wd, _ := os.Getwd()
			path, _ := filepath.Rel(wd, pkg.GoFiles[i])
			if strings.HasPrefix(path, "..") {
				continue
			}
			fmt.Println("---", path, "---")

			//ast.Print(pkg.Fset, f)

			comments := ast.NewCommentMap(pkg.Fset, f, f.Comments)
			astutil.Apply(f, nil, (&typedTransform{pkg, comments, nil}).transform)

			// Apply a second time to deal with type changing from LabelArray to Labels.
			astutil.Apply(f, nil, (&typedTransform{pkg, comments, nil}).transform)
			f.Comments = comments.Comments()

			if *inplace {
				s, err := os.Stat(path)
				if err != nil {
					panic(err)
				}
				out, err := os.OpenFile(path, os.O_TRUNC|os.O_WRONLY, s.Mode())
				if err != nil {
					panic(err)
				}
				format.Node(out, pkg.Fset, f)
				out.Close()
			} else {
				format.Node(os.Stdout, pkg.Fset, f)
			}
		}
	}
}

func callExpr(x ast.Expr, sel string, args ...ast.Expr) ast.Expr {
	return &ast.CallExpr{
		Fun: &ast.SelectorExpr{
			X:   x,
			Sel: &ast.Ident{Name: sel},
		},
		Lparen:   0,
		Args:     args,
		Ellipsis: 0,
		Rparen:   0,
	}
}

func labelsSelector(pos token.Pos, n string) *ast.SelectorExpr {
	return &ast.SelectorExpr{
		X:   &ast.Ident{NamePos: pos, Name: "labels"},
		Sel: &ast.Ident{Name: n},
	}
}

func labelsPkgIdent() *ast.Ident {
	return &ast.Ident{Name: "labels"}
}

func newLabelsExpr(pos token.Pos, args ...ast.Expr) ast.Node {
	if len(args) == 0 {
		return labelsSelector(pos, "Empty")
	} else {
		return callExpr(labelsPkgIdent(), "NewLabels", args...)
	}
}

func extractName(n ast.Node) (x string, xE ast.Expr, name *string) {
	switch n := n.(type) {
	case *ast.Ident:
		name = &n.Name
		xE = n
	case *ast.SelectorExpr:
		xE = n.X
		if id, ok := n.X.(*ast.Ident); ok {
			x = id.Name
		}
		name = &n.Sel.Name
		return
		/*default:
		panic(fmt.Sprintf("extractName: unhandled %T", n))*/
	}
	return
}

func isUnder(x ast.Expr) bool {
	switch x := x.(type) {
	case *ast.Ident:
		return x.Name == "_"
	}
	return false
}

type typedTransform struct {
	pkg          *packages.Package
	comments     ast.CommentMap
	lastFuncType *ast.FuncType
}

var labelsTypeName = "github.com/cilium/cilium/pkg/labels.Labels"
var labelArrayTypeName = "github.com/cilium/cilium/pkg/labels.LabelArray"

func (t *typedTransform) transform(c *astutil.Cursor) bool {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(os.Stderr, "panic at %s\n", t.pkg.Fset.Position(c.Node().Pos()))
			panic(err)
		}
	}()

	n := c.Node()
	scope := func() *types.Scope {
		s := t.pkg.Types.Scope()
		if s == nil {
			return nil
		}
		return s.Innermost(n.Pos())
	}
	lookup := func(x string) string {
		if s := scope(); s != nil {
			if obj := s.Lookup(x); obj != nil {
				return obj.Type().String()
			}
		}
		return ""
	}
	replace := func(new ast.Node) {
		t.comments.Update(c.Node(), new)
		c.Replace(new)
	}
	typeIsLabels := func(n ast.Expr) bool {
		typ := t.pkg.TypesInfo.TypeOf(n)
		if typ == nil {
			return false
		}
		return typ.String() == labelsTypeName
	}
	switch n := n.(type) {
	case *ast.ExprStmt:
		switch n := n.X.(type) {
		case *ast.CallExpr:
			x, xE, name := extractName(n.Fun)
			funType := func() string {
				return lookup(x)
			}
			switch {
			case name != nil && *name == "MergeLabels" && funType() == labelsTypeName:
				// foo.MergeLabels(bar) => foo = labels.Merge(foo, bar)
				switch xE.(type) {
				case *ast.Ident:
					replace(&ast.AssignStmt{
						Lhs: []ast.Expr{xE},
						Tok: token.ASSIGN,
						Rhs: []ast.Expr{
							callExpr(labelsPkgIdent(), "Merge", xE, n.Args[0]),
						},
					})
				}
			}
		}

	case *ast.ReturnStmt:
		if t.lastFuncType == nil || t.lastFuncType.Results == nil {
			return true
		}
		rpos := 0
		for _, f := range t.lastFuncType.Results.List {
			if !typeIsLabels(f.Type) {
				rpos += len(f.Names)
				continue
			}
			for range max(1, len(f.Names)) {
				if rpos >= len(n.Results) {
					// Bail out if we encounter something like this:
					// func foo() (a, b labels.Labels) { return baz() }
					break
				}

				switch e := n.Results[rpos].(type) {
				case *ast.Ident:
					if e.Name == "nil" {
						// Replace the nil with labels.Empty
						n.Results[rpos] = labelsSelector(n.Results[rpos].Pos(), "Empty")
					}
				}
				rpos++
			}
		}

	case *ast.BinaryExpr:
		switch n.Op {
		case token.EQL, token.NEQ:
			if !typeIsLabels(n.X) {
				break
			}
			switch y := n.Y.(type) {
			case *ast.Ident:
				if y.Name == "nil" {
					replace(callExpr(n.X, "IsEmpty"))
				}
			}
		}

	case *ast.Ident:
		switch {
		case n.Name == "nil" && typeIsLabels(n):
			panic("todo rewrite nil")
			//panic(fmt.Sprintf("nil labels, type is %s", t.pkg.TypesInfo.TypeOf(n)))
		case n.Name == "nil":
		}

	case *ast.FuncType:
		if c.Name() == "Type" {
			// Record the last function type coming from a FuncDecl before we
			// traverse into the body. This is not strictly correct for dealing
			// with the untyped nils in return statements, but gets us very close.
			t.lastFuncType = n
		}

	case *ast.CallExpr:
		x, _, name := extractName(n.Fun)
		funType := func() string {
			return lookup(x)
		}
		switch {
		case name == nil:

		case *name == "Labels" && funType() == labelArrayTypeName:
			replace(n.Fun.(*ast.SelectorExpr).X)

		case x == "labels" && *name == "ParseLabelArray":
			*name = "ParseLabels"

		case x == "labels" && *name == "ParseSelectLabelArray":
			*name = "ParseSelectLabelArray"

		case x == "labels" && *name == "NewFrom":
			// NewFrom is meaningless now that Labels is immutable
			replace(n.Args[0])

		case *name == "Equals" && funType() == labelsTypeName:
			// Equals is now Equal to match how it's usually called in Go
			*name = "Equal"

		case *name == "LabelArray" && funType() == labelsTypeName:
			// Remove LabelArray() calls
			switch fun := n.Fun.(type) {
			case *ast.SelectorExpr:
				replace(fun.X)
			}

		case *name == "len":
			typ := t.pkg.TypesInfo.TypeOf(n.Args[0])
			if typ != nil {
				if strings.HasSuffix(typ.String(), "labels.Labels") {
					replace(callExpr(n.Args[0], "Len"))
				}
			}
		}

		/*
			fmt.Printf("call: %+v\n", n)
			fmt.Printf("x: %s, name: %v\n", x, name)
			fmt.Printf("fun: %+v\n", n.Fun)
			fmt.Printf("fun: %T\n", n.Fun)*/

	case *ast.SelectorExpr:
		x, _, name := extractName(n)
		switch {
		/* already done:
		case *name == "Key" && strings.HasSuffix(lookup(x), "labels.Label"):
			c.Replace(callExpr(xId, "Key"))
		case *name == "Source" && strings.HasSuffix(lookup(x), "labels.Label"):
			c.Replace(callExpr(xId, "Source"))
		case *name == "Value" && strings.HasSuffix(lookup(x), "labels.Label"):
			c.Replace(callExpr(xId, "Value"))*/

		case *name == "LabelArray" && x == "labels":
			*name = "Labels"

		case *name == "nil":
			panic("nil")
		}

	case *ast.RangeStmt:
		typP := t.pkg.TypesInfo.TypeOf(n.X)
		if typP == nil {
			return true
		}
		typ := typP.String()
		switch {
		case typ == labelsTypeName:
			origKey := n.Key
			n.Key = n.Value
			n.Value = nil
			newX := &ast.CallExpr{
				Lparen: n.X.Pos(),
				Fun: &ast.SelectorExpr{
					X:   n.X,
					Sel: &ast.Ident{Name: "All"},
				},
			}
			t.comments.Update(n.X, newX)
			n.X = newX
			if origKey != nil && !isUnder(origKey) {
				n.Body.List = append([]ast.Stmt{
					&ast.AssignStmt{
						Lhs: []ast.Expr{origKey},
						Tok: token.DEFINE,
						Rhs: []ast.Expr{callExpr(n.Key, "Key")},
					},
				}, n.Body.List...)
			}
		}

	case *ast.ValueSpec:
		switch {
		// _ = lbls[k] => _ = lbls.GetOrEmpty(k)
		case len(n.Names) == 1 && len(n.Values) == 1:
			x := n.Values[0]
			switch ix := x.(type) {
			case *ast.IndexExpr:
				typ := t.pkg.TypesInfo.TypeOf(ix.X).String()
				switch {
				case strings.HasSuffix(typ, "labels.Labels"):
					// _, _ = lbls[k] => _, _ = lbls.Get(k)
					n.Values[0] = callExpr(ix.X, "GetOrEmpty", ix.Index)
				}
			}

			// _, _ = lbls[k] => _, _ = lbls.Get(k)
		case len(n.Names) == 2 && len(n.Values) == 1:
			x := n.Values[0]
			switch ix := x.(type) {
			case *ast.IndexExpr:
				typ := t.pkg.TypesInfo.TypeOf(ix.X).String()
				switch {
				case strings.HasSuffix(typ, "labels.Labels"):
					n.Values[0] = callExpr(ix.X, "Get", ix.Index)
				}
			}

		}

	case *ast.IndexExpr:
		if _, ok := c.Parent().(*ast.ValueSpec); ok {
			// Don't step on the ValueSpec case
			return true
		}

		methodName := "GetOrEmpty"
		if a, ok := c.Parent().(*ast.AssignStmt); ok {
			if len(a.Lhs) == 2 {
				methodName = "Get"
			} else if a.Lhs[0] == n {
				// lbls[k] = ... => lbls = lbls.Add(...)
				// TODO
				return true
			}
		}

		typ := t.pkg.TypesInfo.TypeOf(n.X).String()
		switch {
		case strings.HasSuffix(typ, "labels.Labels"):
			// lbls[k] => lbls.GetOrEmpty(k)
			// The "v, ok = lbls[k]" case is handled in ValueSpec.
			replace(callExpr(n.X, methodName, n.Index))
		}

	case *ast.CompositeLit:
		x, _, name := extractName(n.Type)
		if x != "labels" {
			return true
		}
		switch *name {
		case "Labels":
			for i, e := range n.Elts {
				if e, ok := e.(*ast.KeyValueExpr); ok {
					/*
						switch x := e.Value.(type) {
						case *ast.CallExpr:
							// Clear the positions to not mess up
							// comment formatting.
							x.Lparen = token.NoPos
							x.Ellipsis = token.NoPos
							x.Rparen = token.NoPos
						}*/
					n.Elts[i] = e.Value
				} else {
					return true
				}
			}
			ex := newLabelsExpr(n.Pos(), n.Elts...)
			replace(ex)

		case "LabelArray":
			replace(newLabelsExpr(n.Pos(), n.Elts...))

		}

	}
	return true
}
