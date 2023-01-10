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
	"strconv"
	"sync"
)

// NB(directxman12): most of this is done by the typechecker,
// but it's a bit slow/heavyweight for what we want -- we want
// to resolve external imports *only* if we actually need them.

// Basically, what we do is:
// 1. Map imports to names
// 2. Find all explicit external references (`name.type`)
// 3. Find all referenced packages by merging explicit references and dot imports
// 4. Only type-check those packages
// 5. Ignore type-checking errors from the missing packages, because we won't ever
//    touch unloaded types (they're probably used in ignored fields/types, variables, or functions)
//    (done using PrintErrors with an ignore argument from the caller).
// 6. Notice any actual type-checking errors via invalid types

// importsMap saves import aliases, mapping them to underlying packages.
type importsMap struct {
	// dotImports maps package IDs to packages for any packages that have/ been imported as `.`
	dotImports map[string]*Package
	// byName maps package aliases or names to the underlying package.
	byName map[string]*Package
}

// mapImports maps imports from the names they use in the given file to the underlying package,
// using a map of package import paths to packages (generally from Package.Imports()).
func mapImports(file *ast.File, importedPkgs map[string]*Package) (*importsMap, error) {
	m := &importsMap{
		dotImports: make(map[string]*Package),
		byName:     make(map[string]*Package),
	}
	for _, importSpec := range file.Imports {
		path, err := strconv.Unquote(importSpec.Path.Value)
		if err != nil {
			return nil, ErrFromNode(err, importSpec.Path)
		}
		importedPkg := importedPkgs[path]
		if importedPkg == nil {
			return nil, ErrFromNode(fmt.Errorf("no such package located"), importSpec.Path)
		}
		if importSpec.Name == nil {
			m.byName[importedPkg.Name] = importedPkg
			continue
		}
		if importSpec.Name.Name == "." {
			m.dotImports[importedPkg.ID] = importedPkg
			continue
		}
		m.byName[importSpec.Name.Name] = importedPkg
	}

	return m, nil
}

// referenceSet finds references to external packages' types in the given file,
// without otherwise calling into the type-checker.  When checking structs,
// it only checks fields with JSON tags.
type referenceSet struct {
	file    *ast.File
	imports *importsMap
	pkg     *Package

	externalRefs map[*Package]struct{}
}

func (r *referenceSet) init() {
	if r.externalRefs == nil {
		r.externalRefs = make(map[*Package]struct{})
	}
}

// NodeFilter filters nodes, accepting them for reference collection
// when true is returned and rejecting them when false is returned.
type NodeFilter func(ast.Node) bool

// collectReferences saves all references to external types in the given info.
func (r *referenceSet) collectReferences(rawType ast.Expr, filterNode NodeFilter) {
	r.init()
	col := &referenceCollector{
		refs:       r,
		filterNode: filterNode,
	}
	ast.Walk(col, rawType)
}

// external saves an external reference to the given named package.
func (r *referenceSet) external(pkgName string) {
	pkg := r.imports.byName[pkgName]
	if pkg == nil {
		r.pkg.AddError(fmt.Errorf("use of unimported package %q", pkgName))
		return
	}
	r.externalRefs[pkg] = struct{}{}
}

// referenceCollector visits nodes in an AST, adding external references to a
// referenceSet.
type referenceCollector struct {
	refs       *referenceSet
	filterNode NodeFilter
}

func (c *referenceCollector) Visit(node ast.Node) ast.Visitor {
	if !c.filterNode(node) {
		return nil
	}
	switch typedNode := node.(type) {
	case *ast.Ident:
		// local reference or dot-import, ignore
		return nil
	case *ast.SelectorExpr:
		pkgName := typedNode.X.(*ast.Ident).Name
		c.refs.external(pkgName)
		return nil
	default:
		return c
	}
}

// allReferencedPackages finds all directly referenced packages in the given package.
func allReferencedPackages(pkg *Package, filterNodes NodeFilter) []*Package {
	pkg.NeedSyntax()
	refsByFile := make(map[*ast.File]*referenceSet)
	for _, file := range pkg.Syntax {
		imports, err := mapImports(file, pkg.Imports())
		if err != nil {
			pkg.AddError(err)
			return nil
		}
		refs := &referenceSet{
			file:    file,
			imports: imports,
			pkg:     pkg,
		}
		refsByFile[file] = refs
	}

	EachType(pkg, func(file *ast.File, decl *ast.GenDecl, spec *ast.TypeSpec) {
		refs := refsByFile[file]
		refs.collectReferences(spec.Type, filterNodes)
	})

	allPackages := make(map[*Package]struct{})
	for _, refs := range refsByFile {
		for _, pkg := range refs.imports.dotImports {
			allPackages[pkg] = struct{}{}
		}
		for ref := range refs.externalRefs {
			allPackages[ref] = struct{}{}
		}
	}

	res := make([]*Package, 0, len(allPackages))
	for pkg := range allPackages {
		res = append(res, pkg)
	}
	return res
}

// TypeChecker performs type-checking on a limitted subset of packages by
// checking each package's types' externally-referenced types, and only
// type-checking those packages.
type TypeChecker struct {
	// NodeFilters are used to filter the set of references that are followed
	// when typechecking.  If any of the filters returns true for a given node,
	// its package will be added to the set of packages to check.
	//
	// If no filters are specified, all references are followed (this may be slow).
	//
	// Modifying this after the first call to check may yield strange/invalid
	// results.
	NodeFilters []NodeFilter

	checkedPackages map[*Package]struct{}
	sync.Mutex
}

// Check type-checks the given package and all packages referenced by types
// that pass through (have true returned by) any of the NodeFilters.
func (c *TypeChecker) Check(root *Package) {
	c.init()

	// use a sub-checker with the appropriate settings
	(&TypeChecker{
		NodeFilters:     c.NodeFilters,
		checkedPackages: c.checkedPackages,
	}).check(root)
}

func (c *TypeChecker) isNodeInteresting(node ast.Node) bool {
	// no filters --> everything is important
	if len(c.NodeFilters) == 0 {
		return true
	}

	// otherwise, passing through any one filter means this node is important
	for _, filter := range c.NodeFilters {
		if filter(node) {
			return true
		}
	}
	return false
}

func (c *TypeChecker) init() {
	if c.checkedPackages == nil {
		c.checkedPackages = make(map[*Package]struct{})
	}
}

// check recursively type-checks the given package, only loading packages that
// are actually referenced by our types (it's the actual implementation of Check,
// without initialization).
func (c *TypeChecker) check(root *Package) {
	root.Lock()
	defer root.Unlock()

	c.Lock()
	_, ok := c.checkedPackages[root]
	c.Unlock()
	if ok {
		return
	}

	refedPackages := allReferencedPackages(root, c.isNodeInteresting)

	// first, resolve imports for all leaf packages...
	var wg sync.WaitGroup
	for _, pkg := range refedPackages {
		wg.Add(1)
		go func(pkg *Package) {
			defer wg.Done()
			c.check(pkg)
		}(pkg)
	}
	wg.Wait()

	// ...then, we can safely type-check ourself
	root.NeedTypesInfo()

	c.Lock()
	defer c.Unlock()
	c.checkedPackages[root] = struct{}{}
}
