/*
Copyright 2019-2022 The Kubernetes Authors.

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
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"golang.org/x/tools/go/packages"
	"k8s.io/apimachinery/pkg/util/sets"
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
			src, err := os.ReadFile(filename)
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
//
// This function will traverse Go module boundaries for roots that are file-
// system paths and end with "...". Please note this feature currently only
// supports roots that are filesystem paths. For more information, please
// refer to the high-level outline of this function's logic:
//
//  1. If no roots are provided then load the working directory and return
//     early.
//
//  2. Otherwise sort the provided roots into two, distinct buckets:
//
//     a. package/module names
//     b. filesystem paths
//
//     A filesystem path is distinguished from a Go package/module name by
//     the same rules as followed by the "go" command. At a high level, a
//     root is a filesystem path IFF it meets ANY of the following criteria:
//
//     * is absolute
//     * begins with .
//     * begins with ..
//
//     For more information please refer to the output of the command
//     "go help packages".
//
//  3. Load the package/module roots as a single call to packages.Load. If
//     there are no filesystem path roots then return early.
//
//  4. For filesystem path roots ending with "...", check to see if its
//     descendants include any nested, Go modules. If so, add the directory
//     that contains the nested Go module to the filesystem path roots.
//
//  5. Load the filesystem path roots and return the load packages for the
//     package/module roots AND the filesystem path roots.
func LoadRootsWithConfig(cfg *packages.Config, roots ...string) ([]*Package, error) {
	l := &loader{
		cfg:      cfg,
		packages: make(map[*packages.Package]*Package),
	}
	l.cfg.Mode |= packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedTypesSizes
	if l.cfg.Fset == nil {
		l.cfg.Fset = token.NewFileSet()
	}
	// put our build flags first so that callers can override them
	l.cfg.BuildFlags = append([]string{"-tags", "ignore_autogenerated"}, l.cfg.BuildFlags...)

	// Visit the import graphs of the loaded, root packages. If an imported
	// package refers to another loaded, root package, then replace the
	// instance of the imported package with a reference to the loaded, root
	// package. This is required to make kubebuilder markers work correctly
	// when multiple root paths are loaded and types from one path reference
	// types from another root path.
	defer func() {
		for i := range l.Roots {
			visitImports(l.Roots, l.Roots[i], nil)
		}
	}()

	// uniquePkgIDs is used to keep track of the discovered packages to be nice
	// and try and prevent packages from showing up twice when nested module
	// support is enabled. there is not harm that comes from this per se, but
	// it makes testing easier when a known number of modules can be asserted
	uniquePkgIDs := sets.Set[string]{}

	// loadPackages returns the Go packages for the provided roots
	//
	// if validatePkgFn is nil, a package will be returned in the slice,
	// otherwise the package is only returned if the result of
	// validatePkgFn(pkg.ID) is truthy
	loadPackages := func(roots ...string) ([]*Package, error) {
		rawPkgs, err := packages.Load(l.cfg, roots...)
		if err != nil {
			loadRoot := l.cfg.Dir
			if l.cfg.Dir == "" {
				loadRoot, _ = os.Getwd()
			}
			return nil, fmt.Errorf("load packages in root %q: %w", loadRoot, err)
		}
		var pkgs []*Package
		for _, rp := range rawPkgs {
			p := l.packageFor(rp)
			if !uniquePkgIDs.Has(p.ID) {
				pkgs = append(pkgs, p)
				uniquePkgIDs.Insert(p.ID)
			}
		}
		return pkgs, nil
	}

	// if no roots were provided then load the current package and return early
	if len(roots) == 0 {
		pkgs, err := loadPackages()
		if err != nil {
			return nil, err
		}
		l.Roots = append(l.Roots, pkgs...)
		return l.Roots, nil
	}

	// pkgRoots is a slice of roots that are package/modules and fspRoots
	// is a slice of roots that are local filesystem paths.
	//
	// please refer to this function's godoc comments for more information on
	// how these two types of roots are distinguished from one another
	var (
		pkgRoots  []string
		fspRoots  []string
		fspRootRx = regexp.MustCompile(`^\.{1,2}`)
	)
	for _, r := range roots {
		if filepath.IsAbs(r) || fspRootRx.MatchString(r) {
			fspRoots = append(fspRoots, r)
		} else {
			pkgRoots = append(pkgRoots, r)
		}
	}

	// handle the package roots by sending them into the packages.Load function
	// all at once. this is more efficient, but cannot be used for the file-
	// system path roots due to them needing a custom, calculated value for the
	// cfg.Dir field
	if len(pkgRoots) > 0 {
		pkgs, err := loadPackages(pkgRoots...)
		if err != nil {
			return nil, err
		}
		l.Roots = append(l.Roots, pkgs...)
	}

	// if there are no filesystem path roots then go ahead and return early
	if len(fspRoots) == 0 {
		return l.Roots, nil
	}

	//
	// at this point we are handling filesystem path roots
	//

	// ensure the cfg.Dir field is reset to its original value upon
	// returning from this function. it should honestly be fine if it is
	// not given most callers will not send in the cfg parameter directly,
	// as it's largely for testing, but still, let's be good stewards.
	defer func(d string) {
		cfg.Dir = d
	}(cfg.Dir)

	// store the value of cfg.Dir so we can use it later if it is non-empty.
	// we need to store it now as the value of cfg.Dir will be updated by
	// a loop below
	cfgDir := cfg.Dir

	// addNestedGoModulesToRoots is given to filepath.WalkDir and adds the
	// directory part of p to the list of filesystem path roots IFF p is the
	// path to a file named "go.mod"
	addNestedGoModulesToRoots := func(
		p string,
		d os.DirEntry,
		e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() && filepath.Base(p) == "go.mod" {
			fspRoots = append(fspRoots, filepath.Join(filepath.Dir(p), "..."))
		}
		return nil
	}

	// in the first pass over the filesystem path roots we:
	//
	//    1. make the root into an absolute path
	//
	//    2. check to see if a root uses the nested path syntax, ex. ...
	//
	//    3. if so, walk the root's descendants, searching for any nested Go
	//       modules
	//
	//    4. if found then the directory containing the Go module is added to
	//       the list of the filesystem path roots
	for i := range fspRoots {
		r := fspRoots[i]

		// clean up the root
		r = filepath.Clean(r)

		// get the absolute path of the root
		if !filepath.IsAbs(r) {
			// if the initial value of cfg.Dir was non-empty then use it when
			// building the absolute path to this root. otherwise use the
			// filepath.Abs function to get the absolute path of the root based
			// on the working directory
			if cfgDir != "" {
				r = filepath.Join(cfgDir, r)
			} else {
				ar, err := filepath.Abs(r)
				if err != nil {
					return nil, err
				}
				r = ar
			}
		}

		// update the root to be an absolute path
		fspRoots[i] = r

		b, d := filepath.Base(r), filepath.Dir(r)

		// if the base element is "..." then it means nested traversal is
		// activated. this can be passed directly to the loader. however, if
		// specified we also want to traverse the path manually to determine if
		// there are any nested Go modules we want to add to the list of file-
		// system path roots to process
		if b == "..." {
			if err := filepath.WalkDir(
				d,
				addNestedGoModulesToRoots); err != nil {
				return nil, err
			}
		}
	}

	// in the second pass over the filesystem path roots we:
	//
	//    1. determine the directory from which to execute the loader
	//
	//    2. update the loader config's Dir property to be the directory from
	//       step one
	//
	//    3. determine whether the root passed to the loader should be "./."
	//       or "./..."
	//
	//    4. execute the loader with the value from step three
	for _, r := range fspRoots {
		b, d := filepath.Base(r), filepath.Dir(r)

		// we want the base part of the path to be either "..." or ".", except
		// Go's filepath utilities clean paths during manipulation, removing the
		// ".". thus, if not "...", let's update the path components so that:
		//
		//   d = r
		//   b = "."
		if b != "..." {
			d = r
			b = "."
		}

		// update the loader configuration's Dir field to the directory part of
		// the root
		l.cfg.Dir = d

		// update the root to be "./..." or "./."
		// (with OS-specific filepath separator). please note filepath.Join
		// would clean up the trailing "." character that we want preserved,
		// hence the more manual path concatenation logic
		r = fmt.Sprintf(".%s%s", string(filepath.Separator), b)

		// load the packages from the roots
		pkgs, err := loadPackages(r)
		if err != nil {
			return nil, err
		}
		l.Roots = append(l.Roots, pkgs...)
	}

	return l.Roots, nil
}

// visitImports walks a dependency graph, replacing imported package
// references with those from the rootPkgs list. This ensures the
// kubebuilder marker generation is handled correctly. For more info,
// please see issue 680.
func visitImports(rootPkgs []*Package, pkg *Package, seen sets.Set[string]) {
	if seen == nil {
		seen = sets.Set[string]{}
	}
	for importedPkgID, importedPkg := range pkg.Imports() {
		for i := range rootPkgs {
			if importedPkgID == rootPkgs[i].ID {
				pkg.imports[importedPkgID] = rootPkgs[i]
			}
		}
		if !seen.Has(importedPkgID) {
			seen.Insert(importedPkgID)
			visitImports(rootPkgs, importedPkg, seen)
		}
	}
}

// importFunc is an implementation of the single-method
// types.Importer interface based on a function value.
type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }
