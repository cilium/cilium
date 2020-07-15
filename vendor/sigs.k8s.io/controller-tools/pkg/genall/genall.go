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

package genall

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/tools/go/packages"
	"sigs.k8s.io/yaml"

	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// Generators are a list of Generators.
// NB(directxman12): this is a pointer so that we can uniquely identify each
// instance of a generator, even if it's not hashable.  Different *instances*
// of a generator are treated differently.
type Generators []*Generator

// RegisterMarkers registers all markers defined by each of the Generators in
// this list into the given registry.
func (g Generators) RegisterMarkers(reg *markers.Registry) error {
	for _, gen := range g {
		if err := (*gen).RegisterMarkers(reg); err != nil {
			return err
		}
	}
	return nil
}

// Generator knows how to register some set of markers, and then produce
// output artifacts based on loaded code containing those markers,
// sharing common loaded data.
type Generator interface {
	// RegisterMarkers registers all markers needed by this Generator
	// into the given registry.
	RegisterMarkers(into *markers.Registry) error
	// Generate generates artifacts produced by this marker.
	// It's called *after* RegisterMarkers has been called.
	Generate(*GenerationContext) error
}

// HasHelp is some Generator, OutputRule, etc with a help method.
type HasHelp interface {
	// Help returns help for this generator.
	Help() *markers.DefinitionHelp
}

// Runtime collects generators, loaded program data (Collector, root Packages),
// and I/O rules, running them together.
type Runtime struct {
	// Generators are the Generators to be run by this Runtime.
	Generators Generators
	// GenerationContext is the base generation context that's copied
	// to produce the context for each Generator.
	GenerationContext
	// OutputRules defines how to output artifacts for each Generator.
	OutputRules OutputRules
}

// GenerationContext defines the common information needed for each Generator
// to run.
type GenerationContext struct {
	// Collector is the shared marker collector.
	Collector *markers.Collector
	// Roots are the base packages to be processed.
	Roots []*loader.Package
	// Checker is the shared partial type-checker.
	Checker *loader.TypeChecker
	// OutputRule describes how to output artifacts.
	OutputRule
	// InputRule describes how to load associated boilerplate artifacts.
	// It should *not* be used to load source files.
	InputRule
}

// WriteYAML writes the given objects out, serialized as YAML, using the
// context's OutputRule.  Objects are written as separate documents, separated
// from each other by `---` (as per the YAML spec).
func (g GenerationContext) WriteYAML(itemPath string, objs ...interface{}) error {
	out, err := g.Open(nil, itemPath)
	if err != nil {
		return err
	}
	defer out.Close()

	for _, obj := range objs {
		yamlContent, err := yaml.Marshal(obj)
		if err != nil {
			return err
		}
		n, err := out.Write(append([]byte("\n---\n"), yamlContent...))
		if err != nil {
			return err
		}
		if n < len(yamlContent) {
			return io.ErrShortWrite
		}
	}

	return nil
}

// ReadFile reads the given boilerplate artifact using the context's InputRule.
func (g GenerationContext) ReadFile(path string) ([]byte, error) {
	file, err := g.OpenForRead(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ioutil.ReadAll(file)
}

// ForRoots produces a Runtime to run the given generators against the
// given packages.  It outputs to /dev/null by default.
func (g Generators) ForRoots(rootPaths ...string) (*Runtime, error) {
	roots, err := loader.LoadRoots(rootPaths...)
	if err != nil {
		return nil, err
	}
	rt := &Runtime{
		Generators: g,
		GenerationContext: GenerationContext{
			Collector: &markers.Collector{
				Registry: &markers.Registry{},
			},
			Roots:     roots,
			InputRule: InputFromFileSystem,
			Checker:   &loader.TypeChecker{},
		},
		OutputRules: OutputRules{Default: OutputToNothing},
	}
	if err := rt.Generators.RegisterMarkers(rt.Collector.Registry); err != nil {
		return nil, err
	}
	return rt, nil
}

// Run runs the Generators in this Runtime against its packages, printing
// errors (except type errors, which common result from using TypeChecker with
// filters), returning true if errors were found.
func (r *Runtime) Run() bool {
	// TODO(directxman12): we could make this parallel,
	// but we'd need to ensure all underlying machinery is threadsafe
	if len(r.Generators) == 0 {
		fmt.Fprintln(os.Stderr, "no generators to run")
		return true
	}

	for _, gen := range r.Generators {
		ctx := r.GenerationContext // make a shallow copy
		ctx.OutputRule = r.OutputRules.ForGenerator(gen)
		if err := (*gen).Generate(&ctx); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}

	// skip TypeErrors -- they're probably just from partial typechecking in crd-gen
	return loader.PrintErrors(r.Roots, packages.TypeError)
}
