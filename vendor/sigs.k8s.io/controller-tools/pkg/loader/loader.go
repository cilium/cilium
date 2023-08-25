/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package loader

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"io/ioutil"
	"os"
	"sync"

	"golang.org/x/tools/go/packages"
)

// Much of this is strongly inspired by the contents of go/packages,
// except that it allows for lazy loading of syntax and type-checking
// information to speed up cases where full traversal isn't needed.

// PrintErrors print errors associated with all packages
// in the given package graph, starting at the given root
// packages and traversing through all imports.  It will skip
// any errors of the kinds specified in filterKinds.  It will
// return true if any errors were printed.
func PrintErrors(pkgs []*Package, filterKinds ...packages.ErrorKind) bool {
	pkgsRaw := make([]*packages.Package, len(pkgs))
	for i, pkg := range pkgs {
		pkgsRaw[i] = pkg.Package
	}
	toSkip := make(map[packages.ErrorKind]struct{})
	for _, errKind := range filterKinds {
		toSkip[errKind] = struct{}{}
	}
	hadErrors := false
	packages.Visit(pkgsRaw, nil, func(pkgRaw *packages.Package) {
		for _, err := range pkgRaw.Errors {
			if _, skip := toSkip[err.Kind]; skip {
				continue
			}
			hadErrors = true
			fmt.Fprintln(os.Stderr, err)
		}
	})
	return hadErrors
}

// Package is a single, unique Go package that can be
// lazily parsed and type-checked.  Packages should not
// be constructed directly -- instead, use LoadRoots.
// For a given call to LoadRoots, only a single instance
// of each package exists, and thus they may be used as keys
// and for comparison.
type Package struct {
	*packages.Package

	imports map[string]*Package

	loader *loader
	sync.Mutex
}

// Imports returns the imports for the given package, indexed by
// package path (*not* name in any particular file).
func (p *Package) Imports() map[string]*Package {
	if p.imports == nil {
		p.imports = p.loader.packagesFor(p.Package.Imports)
	}

	return p.imports
}

// NeedTypesInfo indicates that type-checking information is needed for this package.
// Actual type-checking information can be accessed via the Types and TypesInfo fields.
func (p *Package) NeedTypesInfo() {
	if p.TypesInfo != nil {
		return
	}
	p.NeedSyntax()
	p.loader.typeCheck(p)
}

// NeedSyntax indicates that a parsed AST is needed for this package.
// Actual ASTs can be accessed via the Syntax field.
func (p *Package) NeedSyntax() {
	if p.Syntax != nil {
		return
	}
	out := make([]*ast.File, len(p.CompiledGoFiles))
	var wg sync.WaitGroup
	wg.Add(len(p.CompiledGoFiles))
	for i, filename := range p.CompiledGoFiles {
		go func(i int, filename string) {
			defer wg.Done()
			src, err := ioutil.ReadFile(filename)
			if err != nil {
				p.AddError(err)
				return
			}
			out[i], err = p.loader.parseFile(filename, src)
			if err != nil {
				p.AddError(err)
				return
			}
		}(i, filename)
	}
	wg.Wait()
	for _, file := range out {
		if file == nil {
			return
		}
	}
	p.Syntax = out
}

// AddError adds an error to the errors associated with the given package.
func (p *Package) AddError(err error) {
	switch typedErr := err.(type) {
	case *os.PathError:
		// file-reading errors
		p.Errors = append(p.Errors, packages.Error{
			Pos:  typedErr.Path + ":1",
			Msg:  typedErr.Err.Error(),
			Kind: packages.ParseError,
		})
	case scanner.ErrorList:
		// parsing/scanning errors
		for _, subErr := range typedErr {
			p.Errors = append(p.Errors, packages.Error{
				Pos:  subErr.Pos.String(),
				Msg:  subErr.Msg,
				Kind: packages.ParseError,
			})
		}
	case types.Error:
		// type-checking errors
		p.Errors = append(p.Errors, packages.Error{
			Pos:  typedErr.Fset.Position(typedErr.Pos).String(),
			Msg:  typedErr.Msg,
			Kind: packages.TypeError,
		})
	case ErrList:
		for _, subErr := range typedErr {
			p.AddError(subErr)
		}
	case PositionedError:
		p.Errors = append(p.Errors, packages.Error{
			Pos:  p.loader.cfg.Fset.Position(typedErr.Pos).String(),
			Msg:  typedErr.Error(),
			Kind: packages.UnknownError,
		})
	default:
		// should only happen for external errors, like ref checking
		p.Errors = append(p.Errors, packages.Error{
			Pos:  p.ID + ":-",
			Msg:  err.Error(),
			Kind: packages.UnknownError,
		})
	}
}

// loader loads packages and their imports.  Loaded packages will have
// type size, imports, and exports file information populated.  Additional
// information, like ASTs and type-checking information, can be accessed
// via methods on individual packages.
type loader struct {
	// Roots are the loaded "root" packages in the package graph loaded via
	// LoadRoots.
	Roots []*Package

	// cfg contains the package loading config (initialized on demand)
	cfg *packages.Config
	// packages contains the cache of Packages indexed by the underlying
	// package.Package, so that we don't ever produce two Packages with
	// the same underlying packages.Package.
	packages   map[*packages.Package]*Package
	packagesMu sync.Mutex
}

// packageFor returns a wrapped Package for the given packages.Package,
// ensuring that there's a one-to-one mapping between the two.
// It's *not* threadsafe -- use packagesFor for that.
func (l *loader) packageFor(pkgRaw *packages.Package) *Package {
	if l.packages[pkgRaw] == nil {
		l.packages[pkgRaw] = &Package{
			Package: pkgRaw,
			loader:  l,
		}
	}
	return l.packages[pkgRaw]
}

// packagesFor returns a map of Package objects for each packages.Package in the input
// map, ensuring that there's a one-to-one mapping between package.Package and Package
// (as per packageFor).
func (l *loader) packagesFor(pkgsRaw map[string]*packages.Package) map[string]*Package {
	l.packagesMu.Lock()
	defer l.packagesMu.Unlock()

	out := make(map[string]*Package, len(pkgsRaw))
	for name, rawPkg := range pkgsRaw {
		out[name] = l.packageFor(rawPkg)
	}
	return out
}

// typeCheck type-checks the given package.
func (l *loader) typeCheck(pkg *Package) {
	// don't conflict with typeCheckFromExportData

	pkg.TypesInfo = &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Implicits:  make(map[ast.Node]types.Object),
		Scopes:     make(map[ast.Node]*types.Scope),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}

	pkg.Fset = l.cfg.Fset
	pkg.Types = types.NewPackage(pkg.PkgPath, pkg.Name)

	importer := importerFunc(func(path string) (*types.Package, error) {
		if path == "unsafe" {
			return types.Unsafe, nil
		}

		// The imports map is keyed by import path.
		importedPkg := pkg.Imports()[path]
		if importedPkg == nil {
			return nil, fmt.Errorf("package %q possibly creates an import loop", path)
		}

		// it's possible to have a call to check in parallel to a call to this
		// if one package in the package graph gets its dependency filtered out,
		// but another doesn't (so one wants a "placeholder" package here, and another
		// wants the full check).
		//
		// Thus, we need to lock here (at least for the time being) to avoid
		// races between the above write to `pkg.Types` and this checking of
		// importedPkg.Types.
		importedPkg.Lock()
		defer importedPkg.Unlock()

		if importedPkg.Types != nil && importedPkg.Types.Complete() {
			return importedPkg.Types, nil
		}

		// if we haven't already loaded typecheck data, we don't care about this package's types
		return types.NewPackage(importedPkg.PkgPath, importedPkg.Name), nil
	})

	var errs []error

	// type-check
	checkConfig := &types.Config{
		Importer: importer,

		IgnoreFuncBodies: true, // we only need decl-level info

		Error: func(err error) {
			errs = append(errs, err)
		},

		Sizes: pkg.TypesSizes,
	}
	if err := types.NewChecker(checkConfig, l.cfg.Fset, pkg.Types, pkg.TypesInfo).Files(pkg.Syntax); err != nil {
		errs = append(errs, err)
	}

	// make sure that if a given sub-import is ill-typed, we mark this package as ill-typed as well.
	illTyped := len(errs) > 0
	if !illTyped {
		for _, importedPkg := range pkg.Imports() {
			if importedPkg.IllTyped {
				illTyped = true
				break
			}
		}
	}
	pkg.IllTyped = illTyped

	// publish errors to the package error list.
	for _, err := range errs {
		pkg.AddError(err)
	}
}

// parseFile parses the given file, including comments.
func (l *loader) parseFile(filename string, src []byte) (*ast.File, error) {
	// skip function bodies
	file, err := parser.ParseFile(l.cfg.Fset, filename, src, parser.AllErrors|parser.ParseComments)
	if err != nil {
		return nil, err
	}

	return file, nil
}

// LoadRoots loads the given "root" packages by path, transitively loading
// and all imports as well.
//
// Loaded packages will have type size, imports, and exports file information
// populated.  Additional information, like ASTs and type-checking information,
// can be accessed via methods on individual packages.
func LoadRoots(roots ...string) ([]*Package, error) {
	return LoadRootsWithConfig(&packages.Config{}, roots...)
}

// LoadRootsWithConfig functions like LoadRoots, except that it allows passing
// a custom loading config.  The config will be modified to suit the needs of
// the loader.
//
// This is generally only useful for use in testing when you need to modify
// loading settings to load from a fake location.
func LoadRootsWithConfig(cfg *packages.Config, roots ...string) ([]*Package, error) {
	l := &loader{
		cfg:      cfg,
		packages: make(map[*packages.Package]*Package),
	}
	l.cfg.Mode |= packages.LoadImports | packages.NeedTypesSizes
	if l.cfg.Fset == nil {
		l.cfg.Fset = token.NewFileSet()
	}
	// put our build flags first so that callers can override them
	l.cfg.BuildFlags = append([]string{"-tags", "ignore_autogenerated"}, l.cfg.BuildFlags...)

	rawPkgs, err := packages.Load(l.cfg, roots...)
	if err != nil {
		return nil, err
	}

	for _, rawPkg := range rawPkgs {
		l.Roots = append(l.Roots, l.packageFor(rawPkg))
	}

	return l.Roots, nil
}

// importFunc is an implementation of the single-method
// types.Importer interface based on a function value.
type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }
