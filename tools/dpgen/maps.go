// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	_ "embed"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"slices"
	"text/template"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/spf13/cobra"
)

const (
	mapKVFile      = "mapkv.btf"
	mapsGoFile     = "maps_generated.go"
	mapsGoTestFile = "maps_generated_test.go"
)

// runMaps is the main entry point for the maps command.
//
// It loads eBPF object files from the given paths, extracts MapSpecs, generates
// combined BTF for map keys and values, and renders Go code for the map
// specifications.
func runMaps(cmd *cobra.Command, args []string) error {
	// Outer maps are maps returned by LoadMapSpecs.
	outer := make(map[string]*ebpf.MapSpec)

	// Inner maps need a constructor but are not returned as part of LoadMapSpecs.
	// They are instantiated to serve as templates for MapSpec.InnerMap.
	inner := make(map[string]*ebpf.MapSpec)

	bb, err := btf.NewBuilder(nil)
	if err != nil {
		return fmt.Errorf("creating BTF builder: %w", err)
	}

	if err = bb.EnableDeduplication(); err != nil {
		return fmt.Errorf("enabling BTF deduplication: %w", err)
	}

	for p := range glob(args) {
		cs, err := ebpf.LoadCollectionSpec(p)
		if err != nil {
			return fmt.Errorf("loading CollectionSpec %s: %w", p, err)
		}

		// Iterate MapSpecs in sorted order to guarantee deterministic output of the
		// generated BTF blob. If types get added in random order, the resulting
		// contents of the BTF blob will differ between runs.
		for spec := range sortedMapSpecs(cs.Maps) {
			if !needMapSpec(spec) {
				continue
			}

			// Check for compatibility with existing MapSpecs of the same name before
			// adding.
			if existing, ok := outer[spec.Name]; ok {
				if err := mapSpecCompatible(existing, spec); err != nil {
					return fmt.Errorf("incompatible map %s across BPF objects: %w", spec.Name, err)
				}
			}
			outer[spec.Name] = spec

			if err := addMapKV(bb, spec); err != nil {
				return err
			}

			if spec.InnerMap != nil {
				name := spec.InnerMap.Name
				if existing, ok := inner[name]; ok {
					if err := mapSpecCompatible(existing, spec.InnerMap); err != nil {
						return fmt.Errorf("incompatible inner map %s across BPF objects: %w", name, err)
					}
				}
				inner[name] = spec.InnerMap

				if err := addMapKV(bb, spec.InnerMap); err != nil {
					return err
				}
			}
		}
	}

	btfBlob, err := bb.Marshal(nil, nil)
	if err != nil {
		return fmt.Errorf("marshaling combined BTF: %w", err)
	}
	if err := os.WriteFile(path.Join(out, mapKVFile), btfBlob, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", mapKVFile, err)
	}

	f, err := os.OpenFile(mapsGoFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("opening %s: %w", mapsGoFile, err)
	}
	defer f.Close()

	if err := renderMapSpecs(f, outer, inner, goPkg); err != nil {
		return fmt.Errorf("rendering MapSpecs: %w", err)
	}

	f, err = os.OpenFile(mapsGoTestFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("opening %s: %w", mapsGoTestFile, err)
	}
	defer f.Close()

	if err := renderMapSpecsTest(f, goPkg); err != nil {
		return fmt.Errorf("rendering MapSpecs test: %w", err)
	}

	return nil
}

// needMapSpec returns true if the MapSpec should be emitted to the generated
// code.
func needMapSpec(spec *ebpf.MapSpec) bool {
	return spec.Pinning != ebpf.PinNone
}

func renderMapSpecs(w io.Writer, outer, inner map[string]*ebpf.MapSpec, pkg string) error {
	tpl, err := template.New("mapSpec").
		Funcs(map[string]any{
			"camelCase":        camelCase,
			"bpfFlagsToString": bpfFlagsToString,
		}).
		Parse(mapSpecTpl)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	// Generate constructors for both outer and inner maps, but only return outer
	// maps from LoadMapSpecs since inner maps are only used as templates.
	all := maps.Clone(outer)
	maps.Copy(all, inner)

	if err := tpl.Execute(w, struct {
		Package   string
		BTFFile   string
		OuterMaps []*ebpf.MapSpec
		AllMaps   []*ebpf.MapSpec
	}{
		pkg,
		mapKVFile,
		slices.SortedFunc(maps.Values(outer), mapSpecByName),
		slices.SortedFunc(maps.Values(all), mapSpecByName),
	}); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	return nil
}

func renderMapSpecsTest(w io.Writer, pkg string) error {
	tpl, err := template.New("mapSpecTest").Parse(mapSpecTestTpl)
	if err != nil {
		return fmt.Errorf("parsing test template: %w", err)
	}

	if err := tpl.Execute(w, struct{ Package string }{pkg}); err != nil {
		return fmt.Errorf("executing test template: %w", err)
	}

	return nil
}

//go:embed maps_generated.go.tpl
var mapSpecTpl string

//go:embed maps_generated_test.go.tpl
var mapSpecTestTpl string
