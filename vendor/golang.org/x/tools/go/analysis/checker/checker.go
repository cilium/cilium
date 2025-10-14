// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package checker provides an analysis driver based on the
// [golang.org/x/tools/go/packages] representation of a set of
// packages and all their dependencies, as produced by
// [packages.Load].
//
// It is the core of multichecker (the multi-analyzer driver),
// singlechecker (the single-analyzer driver often used to provide a
// convenient command alongside each analyzer), and analysistest, the
// test driver.
//
// By contrast, the 'go vet' command is based on unitchecker, an
// analysis driver that uses separate analysis--analogous to separate
// compilation--with file-based intermediate results. Like separate
// compilation, it is more scalable, especially for incremental
// analysis of large code bases. Commands based on multichecker and
// singlechecker are capable of detecting when they are being invoked
// by "go vet -vettool=exe" and instead dispatching to unitchecker.
//
// Programs built using this package will, in general, not be usable
// in that way. This package is intended only for use in applications
// that invoke the analysis driver as a subroutine, and need to insert
// additional steps before or after the analysis.
//
// See the Example of how to build a complete analysis driver program.
package checker

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"go/types"
	"io"
	"iter"
	"log"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/internal"
	"golang.org/x/tools/go/analysis/internal/analysisflags"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/internal/analysisinternal"
)

// Options specifies options that control the analysis driver.
type Options struct {
	// These options correspond to existing flags exposed by multichecker:
	Sequential  bool      // disable parallelism
	SanityCheck bool      // check fact encoding is ok and deterministic
	FactLog     io.Writer // if non-nil, log each exported fact to it

	// TODO(adonovan): expose ReadFile so that an Overlay specified
	// in the [packages.Config] can be communicated via
	// Pass.ReadFile to each Analyzer.
	readFile analysisinternal.ReadFileFunc
}

// Graph holds the results of a round of analysis, including the graph
// of requested actions (analyzers applied to packages) plus any
// dependent actions that it was necessary to compute.
type Graph struct {
	// Roots contains the roots of the action graph.
	// Each node (a, p) in the action graph represents the
	// application of one analyzer a to one package p.
	// (A node thus corresponds to one analysis.Pass instance.)
	// Roots holds one action per element of the product
	// of the analyzers × packages arguments to Analyze,
	// in unspecified order.
	//
	// Each element of Action.Deps represents an edge in the
	// action graph: a dependency from one action to another.
	// An edge of the form (a, p) -> (a, p2) indicates that the
	// analysis of package p requires information ("facts") from
	// the same analyzer applied to one of p's dependencies, p2.
	// An edge of the form (a, p) -> (a2, p) indicates that the
	// analysis of package p requires information ("results")
	// from a different analyzer a2 applied to the same package.
	// These two kind of edges are called "vertical" and "horizontal",
	// respectively.
	Roots []*Action
}

// All returns an iterator over the action graph in depth-first postorder.
//
// Example:
//
//	for act := range graph.All() {
//		...
//	}
func (g *Graph) All() iter.Seq[*Action] {
	return func(yield func(*Action) bool) {
		forEach(g.Roots, func(act *Action) error {
			if !yield(act) {
				return io.EOF // any error will do
			}
			return nil
		}) // ignore error
	}
}

// An Action represents one unit of analysis work by the driver: the
// application of one analysis to one package. It provides the inputs
// to and records the outputs of a single analysis.Pass.
//
// Actions form a DAG, both within a package (as different analyzers
// are applied, either in sequence or parallel), and across packages
// (as dependencies are analyzed).
type Action struct {
	Analyzer    *analysis.Analyzer
	Package     *packages.Package
	IsRoot      bool // whether this is a root node of the graph
	Deps        []*Action
	Result      any   // computed result of Analyzer.run, if any (and if IsRoot)
	Err         error // error result of Analyzer.run
	Diagnostics []analysis.Diagnostic
	Duration    time.Duration // execution time of this step

	opts         *Options
	once         sync.Once
	pass         *analysis.Pass
	objectFacts  map[objectFactKey]analysis.Fact
	packageFacts map[packageFactKey]analysis.Fact
}

func (act *Action) String() string {
	return fmt.Sprintf("%s@%s", act.Analyzer, act.Package)
}

// Analyze runs the specified analyzers on the initial packages.
//
// The initial packages and all dependencies must have been loaded
// using the [packages.LoadAllSyntax] flag, Analyze may need to run
// some analyzer (those that consume and produce facts) on
// dependencies too.
//
// On success, it returns a Graph of actions whose Roots hold one
// item per (a, p) in the cross-product of analyzers and pkgs.
//
// If opts is nil, it is equivalent to new(Options).
func Analyze(analyzers []*analysis.Analyzer, pkgs []*packages.Package, opts *Options) (*Graph, error) {
	if opts == nil {
		opts = new(Options)
	}

	if err := analysis.Validate(analyzers); err != nil {
		return nil, err
	}

	// Construct the action graph.
	//
	// Each graph node (action) is one unit of analysis.
	// Edges express package-to-package (vertical) dependencies,
	// and analysis-to-analysis (horizontal) dependencies.
	type key struct {
		a   *analysis.Analyzer
		pkg *packages.Package
	}
	actions := make(map[key]*Action)

	var mkAction func(a *analysis.Analyzer, pkg *packages.Package) *Action
	mkAction = func(a *analysis.Analyzer, pkg *packages.Package) *Action {
		k := key{a, pkg}
		act, ok := actions[k]
		if !ok {
			act = &Action{Analyzer: a, Package: pkg, opts: opts}

			// Add a dependency on each required analyzers.
			for _, req := range a.Requires {
				act.Deps = append(act.Deps, mkAction(req, pkg))
			}

			// An analysis that consumes/produces facts
			// must run on the package's dependencies too.
			if len(a.FactTypes) > 0 {
				paths := make([]string, 0, len(pkg.Imports))
				for path := range pkg.Imports {
					paths = append(paths, path)
				}
				sort.Strings(paths) // for determinism
				for _, path := range paths {
					dep := mkAction(a, pkg.Imports[path])
					act.Deps = append(act.Deps, dep)
				}
			}

			actions[k] = act
		}
		return act
	}

	// Build nodes for initial packages.
	var roots []*Action
	for _, a := range analyzers {
		for _, pkg := range pkgs {
			root := mkAction(a, pkg)
			root.IsRoot = true
			roots = append(roots, root)
		}
	}

	// Execute the graph in parallel.
	execAll(roots)

	// Ensure that only root Results are visible to caller.
	// (The others are considered temporary intermediaries.)
	// TODO(adonovan): opt: clear them earlier, so we can
	// release large data structures like SSA sooner.
	for _, act := range actions {
		if !act.IsRoot {
			act.Result = nil
		}
	}

	return &Graph{Roots: roots}, nil
}

func init() {
	// Allow analysistest to access Action.pass,
	// for the legacy analysistest.Result data type,
	// and for internal/checker.ApplyFixes to access pass.ReadFile.
	internal.ActionPass = func(x any) *analysis.Pass { return x.(*Action).pass }
}

type objectFactKey struct {
	obj types.Object
	typ reflect.Type
}

type packageFactKey struct {
	pkg *types.Package
	typ reflect.Type
}

func execAll(actions []*Action) {
	var wg sync.WaitGroup
	for _, act := range actions {
		wg.Add(1)
		work := func(act *Action) {
			act.exec()
			wg.Done()
		}
		if act.opts.Sequential {
			work(act)
		} else {
			go work(act)
		}
	}
	wg.Wait()
}

func (act *Action) exec() { act.once.Do(act.execOnce) }

func (act *Action) execOnce() {
	// Analyze dependencies.
	execAll(act.Deps)

	// Record time spent in this node but not its dependencies.
	// In parallel mode, due to GC/scheduler contention, the
	// time is 5x higher than in sequential mode, even with a
	// semaphore limiting the number of threads here.
	// So use -debug=tp.
	t0 := time.Now()
	defer func() { act.Duration = time.Since(t0) }()

	// Report an error if any dependency failed.
	var failed []string
	for _, dep := range act.Deps {
		if dep.Err != nil {
			failed = append(failed, dep.String())
		}
	}
	if failed != nil {
		sort.Strings(failed)
		act.Err = fmt.Errorf("failed prerequisites: %s", strings.Join(failed, ", "))
		return
	}

	// Plumb the output values of the dependencies
	// into the inputs of this action.  Also facts.
	inputs := make(map[*analysis.Analyzer]any)
	act.objectFacts = make(map[objectFactKey]analysis.Fact)
	act.packageFacts = make(map[packageFactKey]analysis.Fact)
	for _, dep := range act.Deps {
		if dep.Package == act.Package {
			// Same package, different analysis (horizontal edge):
			// in-memory outputs of prerequisite analyzers
			// become inputs to this analysis pass.
			inputs[dep.Analyzer] = dep.Result
		} else if dep.Analyzer == act.Analyzer { // (always true)
			// Same analysis, different package (vertical edge):
			// serialized facts produced by prerequisite analysis
			// become available to this analysis pass.
			inheritFacts(act, dep)
		}
	}

	// Quick (nonexhaustive) check that the correct go/packages mode bits were used.
	// (If there were errors, all bets are off.)
	if pkg := act.Package; pkg.Errors == nil {
		if pkg.Name == "" || pkg.PkgPath == "" || pkg.Types == nil || pkg.Fset == nil || pkg.TypesSizes == nil {
			panic("packages must be loaded with packages.LoadSyntax mode")
		}
	}

	module := &analysis.Module{} // possibly empty (non nil) in go/analysis drivers.
	if mod := act.Package.Module; mod != nil {
		module.Path = mod.Path
		module.Version = mod.Version
		module.GoVersion = mod.GoVersion
	}

	// Run the analysis.
	pass := &analysis.Pass{
		Analyzer:     act.Analyzer,
		Fset:         act.Package.Fset,
		Files:        act.Package.Syntax,
		OtherFiles:   act.Package.OtherFiles,
		IgnoredFiles: act.Package.IgnoredFiles,
		Pkg:          act.Package.Types,
		TypesInfo:    act.Package.TypesInfo,
		TypesSizes:   act.Package.TypesSizes,
		TypeErrors:   act.Package.TypeErrors,
		Module:       module,

		ResultOf: inputs,
		Report: func(d analysis.Diagnostic) {
			// Assert that SuggestedFixes are well formed.
			if err := analysisinternal.ValidateFixes(act.Package.Fset, act.Analyzer, d.SuggestedFixes); err != nil {
				panic(err)
			}
			act.Diagnostics = append(act.Diagnostics, d)
		},
		ImportObjectFact:  act.ObjectFact,
		ExportObjectFact:  act.exportObjectFact,
		ImportPackageFact: act.PackageFact,
		ExportPackageFact: act.exportPackageFact,
		AllObjectFacts:    act.AllObjectFacts,
		AllPackageFacts:   act.AllPackageFacts,
	}
	readFile := os.ReadFile
	if act.opts.readFile != nil {
		readFile = act.opts.readFile
	}
	pass.ReadFile = analysisinternal.CheckedReadFile(pass, readFile)
	act.pass = pass

	act.Result, act.Err = func() (any, error) {
		if act.Package.IllTyped && !pass.Analyzer.RunDespiteErrors {
			return nil, fmt.Errorf("analysis skipped due to errors in package")
		}

		result, err := pass.Analyzer.Run(pass)
		if err != nil {
			return nil, err
		}

		// correct result type?
		if got, want := reflect.TypeOf(result), pass.Analyzer.ResultType; got != want {
			return nil, fmt.Errorf(
				"internal error: on package %s, analyzer %s returned a result of type %v, but declared ResultType %v",
				pass.Pkg.Path(), pass.Analyzer, got, want)
		}

		// resolve diagnostic URLs
		for i := range act.Diagnostics {
			url, err := analysisflags.ResolveURL(act.Analyzer, act.Diagnostics[i])
			if err != nil {
				return nil, err
			}
			act.Diagnostics[i].URL = url
		}
		return result, nil
	}()

	// Help detect (disallowed) calls after Run.
	pass.ExportObjectFact = nil
	pass.ExportPackageFact = nil
}

// inheritFacts populates act.facts with
// those it obtains from its dependency, dep.
func inheritFacts(act, dep *Action) {
	for key, fact := range dep.objectFacts {
		// Filter out facts related to objects
		// that are irrelevant downstream
		// (equivalently: not in the compiler export data).
		if !exportedFrom(key.obj, dep.Package.Types) {
			if false {
				log.Printf("%v: discarding %T fact from %s for %s: %s", act, fact, dep, key.obj, fact)
			}
			continue
		}

		// Optionally serialize/deserialize fact
		// to verify that it works across address spaces.
		if act.opts.SanityCheck {
			encodedFact, err := codeFact(fact)
			if err != nil {
				log.Panicf("internal error: encoding of %T fact failed in %v", fact, act)
			}
			fact = encodedFact
		}

		if false {
			log.Printf("%v: inherited %T fact for %s: %s", act, fact, key.obj, fact)
		}
		act.objectFacts[key] = fact
	}

	for key, fact := range dep.packageFacts {
		// TODO: filter out facts that belong to
		// packages not mentioned in the export data
		// to prevent side channels.
		//
		// The Pass.All{Object,Package}Facts accessors expose too much:
		// all facts, of all types, for all dependencies in the action
		// graph. Not only does the representation grow quadratically,
		// but it violates the separate compilation paradigm, allowing
		// analysis implementations to communicate with indirect
		// dependencies that are not mentioned in the export data.
		//
		// It's not clear how to fix this short of a rather expensive
		// filtering step after each action that enumerates all the
		// objects that would appear in export data, and deletes
		// facts associated with objects not in this set.

		// Optionally serialize/deserialize fact
		// to verify that it works across address spaces
		// and is deterministic.
		if act.opts.SanityCheck {
			encodedFact, err := codeFact(fact)
			if err != nil {
				log.Panicf("internal error: encoding of %T fact failed in %v", fact, act)
			}
			fact = encodedFact
		}

		if false {
			log.Printf("%v: inherited %T fact for %s: %s", act, fact, key.pkg.Path(), fact)
		}
		act.packageFacts[key] = fact
	}
}

// codeFact encodes then decodes a fact,
// just to exercise that logic.
func codeFact(fact analysis.Fact) (analysis.Fact, error) {
	// We encode facts one at a time.
	// A real modular driver would emit all facts
	// into one encoder to improve gob efficiency.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(fact); err != nil {
		return nil, err
	}

	// Encode it twice and assert that we get the same bits.
	// This helps detect nondeterministic Gob encoding (e.g. of maps).
	var buf2 bytes.Buffer
	if err := gob.NewEncoder(&buf2).Encode(fact); err != nil {
		return nil, err
	}
	if !bytes.Equal(buf.Bytes(), buf2.Bytes()) {
		return nil, fmt.Errorf("encoding of %T fact is nondeterministic", fact)
	}

	new := reflect.New(reflect.TypeOf(fact).Elem()).Interface().(analysis.Fact)
	if err := gob.NewDecoder(&buf).Decode(new); err != nil {
		return nil, err
	}
	return new, nil
}

// exportedFrom reports whether obj may be visible to a package that imports pkg.
// This includes not just the exported members of pkg, but also unexported
// constants, types, fields, and methods, perhaps belonging to other packages,
// that find there way into the API.
// This is an overapproximation of the more accurate approach used by
// gc export data, which walks the type graph, but it's much simpler.
//
// TODO(adonovan): do more accurate filtering by walking the type graph.
func exportedFrom(obj types.Object, pkg *types.Package) bool {
	switch obj := obj.(type) {
	case *types.Func:
		return obj.Exported() && obj.Pkg() == pkg ||
			obj.Type().(*types.Signature).Recv() != nil
	case *types.Var:
		if obj.IsField() {
			return true
		}
		// we can't filter more aggressively than this because we need
		// to consider function parameters exported, but have no way
		// of telling apart function parameters from local variables.
		return obj.Pkg() == pkg
	case *types.TypeName, *types.Const:
		return true
	}
	return false // Nil, Builtin, Label, or PkgName
}

// ObjectFact retrieves a fact associated with obj,
// and returns true if one was found.
// Given a value ptr of type *T, where *T satisfies Fact,
// ObjectFact copies the value to *ptr.
//
// See documentation at ImportObjectFact field of [analysis.Pass].
func (act *Action) ObjectFact(obj types.Object, ptr analysis.Fact) bool {
	if obj == nil {
		panic("nil object")
	}
	key := objectFactKey{obj, factType(ptr)}
	if v, ok := act.objectFacts[key]; ok {
		reflect.ValueOf(ptr).Elem().Set(reflect.ValueOf(v).Elem())
		return true
	}
	return false
}

// exportObjectFact implements Pass.ExportObjectFact.
func (act *Action) exportObjectFact(obj types.Object, fact analysis.Fact) {
	if act.pass.ExportObjectFact == nil {
		log.Panicf("%s: Pass.ExportObjectFact(%s, %T) called after Run", act, obj, fact)
	}

	if obj.Pkg() != act.Package.Types {
		log.Panicf("internal error: in analysis %s of package %s: Fact.Set(%s, %T): can't set facts on objects belonging another package",
			act.Analyzer, act.Package, obj, fact)
	}

	key := objectFactKey{obj, factType(fact)}
	act.objectFacts[key] = fact // clobber any existing entry
	if log := act.opts.FactLog; log != nil {
		objstr := types.ObjectString(obj, (*types.Package).Name)
		fmt.Fprintf(log, "%s: object %s has fact %s\n",
			act.Package.Fset.Position(obj.Pos()), objstr, fact)
	}
}

// AllObjectFacts returns a new slice containing all object facts of
// the analysis's FactTypes in unspecified order.
//
// See documentation at AllObjectFacts field of [analysis.Pass].
func (act *Action) AllObjectFacts() []analysis.ObjectFact {
	facts := make([]analysis.ObjectFact, 0, len(act.objectFacts))
	for k, fact := range act.objectFacts {
		facts = append(facts, analysis.ObjectFact{Object: k.obj, Fact: fact})
	}
	return facts
}

// PackageFact retrieves a fact associated with package pkg,
// which must be this package or one of its dependencies.
//
// See documentation at ImportObjectFact field of [analysis.Pass].
func (act *Action) PackageFact(pkg *types.Package, ptr analysis.Fact) bool {
	if pkg == nil {
		panic("nil package")
	}
	key := packageFactKey{pkg, factType(ptr)}
	if v, ok := act.packageFacts[key]; ok {
		reflect.ValueOf(ptr).Elem().Set(reflect.ValueOf(v).Elem())
		return true
	}
	return false
}

// exportPackageFact implements Pass.ExportPackageFact.
func (act *Action) exportPackageFact(fact analysis.Fact) {
	if act.pass.ExportPackageFact == nil {
		log.Panicf("%s: Pass.ExportPackageFact(%T) called after Run", act, fact)
	}

	key := packageFactKey{act.pass.Pkg, factType(fact)}
	act.packageFacts[key] = fact // clobber any existing entry
	if log := act.opts.FactLog; log != nil {
		fmt.Fprintf(log, "%s: package %s has fact %s\n",
			act.Package.Fset.Position(act.pass.Files[0].Pos()), act.pass.Pkg.Path(), fact)
	}
}

func factType(fact analysis.Fact) reflect.Type {
	t := reflect.TypeOf(fact)
	if t.Kind() != reflect.Pointer {
		log.Fatalf("invalid Fact type: got %T, want pointer", fact)
	}
	return t
}

// AllPackageFacts returns a new slice containing all package
// facts of the analysis's FactTypes in unspecified order.
//
// See documentation at AllPackageFacts field of [analysis.Pass].
func (act *Action) AllPackageFacts() []analysis.PackageFact {
	facts := make([]analysis.PackageFact, 0, len(act.packageFacts))
	for k, fact := range act.packageFacts {
		facts = append(facts, analysis.PackageFact{Package: k.pkg, Fact: fact})
	}
	return facts
}

// forEach is a utility function for traversing the action graph. It
// applies function f to each action in the graph reachable from
// roots, in depth-first postorder. If any call to f returns an error,
// the traversal is aborted and ForEach returns the error.
func forEach(roots []*Action, f func(*Action) error) error {
	seen := make(map[*Action]bool)
	var visitAll func(actions []*Action) error
	visitAll = func(actions []*Action) error {
		for _, act := range actions {
			if !seen[act] {
				seen[act] = true
				if err := visitAll(act.Deps); err != nil {
					return err
				}
				if err := f(act); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return visitAll(roots)
}
