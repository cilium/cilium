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
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/tools/go/packages"
	rawyaml "gopkg.in/yaml.v2"

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

// CheckFilters returns the set of NodeFilters for all Generators that
// implement NeedsTypeChecking.
func (g Generators) CheckFilters() []loader.NodeFilter {
	var filters []loader.NodeFilter
	for _, gen := range g {
		withFilter, needsChecking := (*gen).(NeedsTypeChecking)
		if !needsChecking {
			continue
		}
		filters = append(filters, withFilter.CheckFilter())
	}
	return filters
}

// NeedsTypeChecking indicates that a particular generator needs & has opinions
// on typechecking.  If this is not implemented, a generator will be given a
// context with a nil typechecker.
type NeedsTypeChecking interface {
	// CheckFilter indicates the loader.NodeFilter (if any) that should be used
	// to prune out unused types/packages when type-checking (nodes for which
	// the filter returns true are considered "interesting").  This filter acts
	// as a baseline -- all types the pass through this filter will be checked,
	// but more than that may also be checked due to other generators' filters.
	CheckFilter() loader.NodeFilter
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
	// ErrorWriter defines where to write error messages.
	ErrorWriter io.Writer
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

// WriteYAMLOptions implements the Options Pattern for WriteYAML.
type WriteYAMLOptions struct {
	transform func(obj map[string]interface{}) error
}

// WithTransform applies a transformation to objects just before writing them.
func WithTransform(transform func(obj map[string]interface{}) error) *WriteYAMLOptions {
	return &WriteYAMLOptions{
		transform: transform,
	}
}

// TransformRemoveCreationTimestamp ensures we do not write the metadata.creationTimestamp field.
func TransformRemoveCreationTimestamp(obj map[string]interface{}) error {
	metadata := obj["metadata"].(map[interface{}]interface{})
	delete(metadata, "creationTimestamp")
	return nil
}

// WriteYAML writes the given objects out, serialized as YAML, using the
// context's OutputRule.  Objects are written as separate documents, separated
// from each other by `---` (as per the YAML spec).
func (g GenerationContext) WriteYAML(itemPath, headerText string, objs []interface{}, options ...*WriteYAMLOptions) error {
	out, err := g.Open(nil, itemPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.Write([]byte(headerText))
	if err != nil {
		return err
	}

	for _, obj := range objs {
		yamlContent, err := yamlMarshal(obj, options...)
		if err != nil {
			return err
		}
		n, err := out.Write(append([]byte("---\n"), yamlContent...))
		if err != nil {
			return err
		}
		if n < len(yamlContent) {
			return io.ErrShortWrite
		}
	}

	return nil
}

// yamlMarshal is based on sigs.k8s.io/yaml.Marshal, but allows for transforming the final data before writing.
func yamlMarshal(o interface{}, options ...*WriteYAMLOptions) ([]byte, error) {
	j, err := json.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("error marshaling into JSON: %v", err)
	}

	return yamlJSONToYAMLWithFilter(j, options...)
}

// yamlJSONToYAMLWithFilter is based on sigs.k8s.io/yaml.JSONToYAML, but allows for transforming the final data before writing.
func yamlJSONToYAMLWithFilter(j []byte, options ...*WriteYAMLOptions) ([]byte, error) {
	// Convert the JSON to an object.
	var jsonObj map[string]interface{}
	// We are using yaml.Unmarshal here (instead of json.Unmarshal) because the
	// Go JSON library doesn't try to pick the right number type (int, float,
	// etc.) when unmarshalling to interface{}, it just picks float64
	// universally. go-yaml does go through the effort of picking the right
	// number type, so we can preserve number type throughout this process.
	if err := rawyaml.Unmarshal(j, &jsonObj); err != nil {
		return nil, err
	}

	for _, option := range options {
		if option.transform != nil {
			if err := option.transform(jsonObj); err != nil {
				return nil, err
			}
		}
	}

	// Marshal this object into YAML.
	return rawyaml.Marshal(jsonObj)
}

// ReadFile reads the given boilerplate artifact using the context's InputRule.
func (g GenerationContext) ReadFile(path string) ([]byte, error) {
	file, err := g.OpenForRead(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
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
			Checker: &loader.TypeChecker{
				NodeFilters: g.CheckFilters(),
			},
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

	if r.ErrorWriter == nil {
		r.ErrorWriter = os.Stderr
	}
	if len(r.Generators) == 0 {
		fmt.Fprintln(r.ErrorWriter, "no generators to run")
		return true
	}

	hadErrs := false
	for _, gen := range r.Generators {
		ctx := r.GenerationContext // make a shallow copy
		ctx.OutputRule = r.OutputRules.ForGenerator(gen)

		// don't pass a typechecker to generators that don't provide a filter
		// to avoid accidents
		if _, needsChecking := (*gen).(NeedsTypeChecking); !needsChecking {
			ctx.Checker = nil
		}

		if err := (*gen).Generate(&ctx); err != nil {
			fmt.Fprintln(r.ErrorWriter, err)
			hadErrs = true
		}
	}

	// skip TypeErrors -- they're probably just from partial typechecking in crd-gen
	return loader.PrintErrors(r.Roots, packages.TypeError) || hadErrs
}
