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
	"os"
	"path/filepath"

	"sigs.k8s.io/controller-tools/pkg/loader"
)

// nopCloser is a WriteCloser whose Close
// is a no-op.
type nopCloser struct {
	io.Writer
}

func (n nopCloser) Close() error {
	return nil
}

// DirectoryPerGenerator produces output rules mapping output to a different subdirectory
// of the given base directory for each generator (with each subdirectory specified as
// the key in the input map).
func DirectoryPerGenerator(base string, generators map[string]*Generator) OutputRules {
	rules := OutputRules{
		Default:     OutputArtifacts{Config: OutputToDirectory(base)},
		ByGenerator: make(map[*Generator]OutputRule, len(generators)),
	}

	for name, gen := range generators {
		rules.ByGenerator[gen] = OutputArtifacts{
			Config: OutputToDirectory(filepath.Join(base, name)),
		}
	}

	return rules
}

// OutputRules defines how to output artificats on a per-generator basis.
type OutputRules struct {
	// Default is the output rule used when no specific per-generator overrides match.
	Default OutputRule
	// ByGenerator contains specific per-generator overrides.
	// NB(directxman12): this is a pointer to avoid issues if a given Generator becomes unhashable
	// (interface values compare by "dereferencing" their internal pointer first, whereas pointers
	// compare by the actual pointer itself).
	ByGenerator map[*Generator]OutputRule
}

// ForGenerator returns the output rule that should be used
// by the given Generator.
func (o OutputRules) ForGenerator(gen *Generator) OutputRule {
	if forGen, specific := o.ByGenerator[gen]; specific {
		return forGen
	}
	return o.Default
}

// OutputRule defines how to output artifacts from a generator.
type OutputRule interface {
	// Open opens the given artifact path for writing.  If a package is passed,
	// the artifact is considered to be used as part of the package (e.g.
	// generated code), while a nil package indicates that the artifact is
	// config (or something else not involved in Go compilation).
	Open(pkg *loader.Package, path string) (io.WriteCloser, error)
}

// OutputToNothing skips outputting anything.
var OutputToNothing = outputToNothing{}

// +controllertools:marker:generateHelp:category=""

// outputToNothing skips outputting anything.
type outputToNothing struct{}

func (o outputToNothing) Open(_ *loader.Package, _ string) (io.WriteCloser, error) {
	return nopCloser{io.Discard}, nil
}

// +controllertools:marker:generateHelp:category=""

// OutputToDirectory outputs each artifact to the given directory, regardless
// of if it's package-associated or not.
type OutputToDirectory string

func (o OutputToDirectory) Open(_ *loader.Package, itemPath string) (io.WriteCloser, error) {
	// ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(filepath.Join(string(o), itemPath)), os.ModePerm); err != nil {
		return nil, err
	}
	path := filepath.Join(string(o), itemPath)
	return os.Create(path)
}

// OutputToStdout outputs everything to standard-out, with no separation.
//
// Generally useful for single-artifact outputs.
var OutputToStdout = outputToStdout{}

// +controllertools:marker:generateHelp:category=""

// outputToStdout outputs everything to standard-out, with no separation.
//
// Generally useful for single-artifact outputs.
type outputToStdout struct{}

func (o outputToStdout) Open(_ *loader.Package, _ string) (io.WriteCloser, error) {
	return nopCloser{os.Stdout}, nil
}

// +controllertools:marker:generateHelp:category=""

// OutputArtifacts outputs artifacts to different locations, depending on
// whether they're package-associated or not.
//
// Non-package associated artifacts
// are output to the Config directory, while package-associated ones are output
// to their package's source files' directory, unless an alternate path is
// specified in Code.
type OutputArtifacts struct {
	// Config points to the directory to which to write configuration.
	Config OutputToDirectory
	// Code overrides the directory in which to write new code (defaults to where the existing code lives).
	Code OutputToDirectory `marker:",optional"`
}

func (o OutputArtifacts) Open(pkg *loader.Package, itemPath string) (io.WriteCloser, error) {
	if pkg == nil {
		return o.Config.Open(pkg, itemPath)
	}

	if o.Code != "" {
		return o.Code.Open(pkg, itemPath)
	}

	if len(pkg.CompiledGoFiles) == 0 {
		return nil, fmt.Errorf("cannot output to a package with no path on disk")
	}
	outDir := filepath.Dir(pkg.CompiledGoFiles[0])
	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		if err := os.MkdirAll(outDir, os.ModePerm); err != nil {
			return nil, err
		}
	}

	outPath := filepath.Join(outDir, itemPath)
	return os.Create(outPath)
}
