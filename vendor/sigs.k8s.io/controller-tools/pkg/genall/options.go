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
	"maps"
	"strings"

	"golang.org/x/tools/go/packages"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

var (
	InputPathsMarker = markers.Must(markers.MakeDefinition("paths", markers.DescribesPackage, InputPaths(nil)))
)

// +controllertools:marker:generateHelp:category=""

// InputPaths represents paths and go-style path patterns to use as package roots.
//
// Multiple paths can be specified using "{path1, path2, path3}".
type InputPaths []string

// RegisterOptionsMarkers registers "mandatory" options markers for FromOptions into the given registry.
// At this point, that's just InputPaths.
func RegisterOptionsMarkers(into *markers.Registry) error {
	if err := into.Register(InputPathsMarker); err != nil {
		return err
	}
	// NB(directxman12): we make this optional so we don't have a bootstrap problem with helpgen
	if helpGiver, hasHelp := ((any)(InputPaths(nil))).(HasHelp); hasHelp {
		into.AddHelp(InputPathsMarker, helpGiver.Help())
	}
	return nil
}

// RegistryFromOptions produces just the marker registry that would be used by FromOptions, without
// attempting to produce a full Runtime.  This can be useful if you want to display help without
// trying to load roots.
func RegistryFromOptions(optionsRegistry *markers.Registry, options []string) (*markers.Registry, error) {
	protoRt, err := protoFromOptions(optionsRegistry, options)
	if err != nil {
		return nil, err
	}
	reg := &markers.Registry{}
	if err := protoRt.Generators.RegisterMarkers(reg); err != nil {
		return nil, err
	}
	return reg, nil
}

// FromOptions parses the options from markers stored in the given registry out into a runtime.
// The markers in the registry must be either
//
// a) Generators
// b) OutputRules
// c) InputPaths
//
// The paths specified in InputPaths are loaded as package roots, and the combined with
// the generators and the specified output rules to produce a runtime that can be run or
// further modified.  Not default generators are used if none are specified -- you can check
// the output and rerun for that.
func FromOptions(optionsRegistry *markers.Registry, options []string) (*Runtime, error) {
	return FromOptionsWithConfig(&packages.Config{}, optionsRegistry, options)
}

func FromOptionsWithConfig(cfg *packages.Config, optionsRegistry *markers.Registry, options []string) (*Runtime, error) {
	protoRt, err := protoFromOptions(optionsRegistry, options)
	if err != nil {
		return nil, err
	}

	// make the runtime
	genRuntime, err := protoRt.Generators.ForRootsWithConfig(cfg, protoRt.Paths...)
	if err != nil {
		return nil, err
	}

	// attempt to figure out what the user wants without a lot of verbose specificity:
	// if the user specifies a default rule, assume that they probably want to fall back
	// to that.  Otherwise, assume that they just wanted to customize one option from the
	// set, and leave the rest in the standard configuration.
	if protoRt.OutputRules.Default != nil {
		genRuntime.OutputRules = protoRt.OutputRules
		return genRuntime, nil
	}

	outRules := DirectoryPerGenerator("config", protoRt.GeneratorsByName)
	maps.Copy(outRules.ByGenerator, protoRt.OutputRules.ByGenerator)

	genRuntime.OutputRules = outRules
	return genRuntime, nil
}

// protoFromOptions returns a proto-Runtime from the given options registry and
// options set.  This can then be used to construct an actual Runtime.  See the
// FromOptions function for more details about how the options work.
func protoFromOptions(optionsRegistry *markers.Registry, options []string) (protoRuntime, error) {
	var gens Generators
	rules := OutputRules{
		ByGenerator: make(map[*Generator]OutputRule),
	}
	var paths []string

	// collect the generators first, so that we can key the output on the actual
	// generator, which matters if there's settings in the gen object and it's not a pointer.
	outputByGen := make(map[string]OutputRule)
	gensByName := make(map[string]*Generator)

	for _, rawOpt := range options {
		if rawOpt[0] != '+' {
			rawOpt = "+" + rawOpt // add a `+` to make it acceptable for usage with the registry
		}
		defn := optionsRegistry.Lookup(rawOpt, markers.DescribesPackage)
		if defn == nil {
			return protoRuntime{}, fmt.Errorf("unknown option %q", rawOpt[1:])
		}

		val, err := defn.Parse(rawOpt)
		if err != nil {
			return protoRuntime{}, fmt.Errorf("unable to parse option %q: %w", rawOpt[1:], err)
		}

		switch val := val.(type) {
		case Generator:
			gens = append(gens, &val)
			if _, alreadyExists := gensByName[defn.Name]; alreadyExists {
				return protoRuntime{}, fmt.Errorf("multiple instances of '%s' generator specified", defn.Name)
			}
			gensByName[defn.Name] = &val
		case OutputRule:
			_, genName := splitOutputRuleOption(defn.Name)
			if genName == "" {
				// it's a default rule
				rules.Default = val
				continue
			}

			outputByGen[genName] = val
			continue
		case InputPaths:
			paths = append(paths, val...)
		default:
			return protoRuntime{}, fmt.Errorf("unknown option marker %q", defn.Name)
		}
	}

	// actually associate the rules now that we know the generators
	for genName, outputRule := range outputByGen {
		gen, knownGen := gensByName[genName]
		if !knownGen {
			return protoRuntime{}, fmt.Errorf("non-invoked generator %q", genName)
		}

		rules.ByGenerator[gen] = outputRule
	}

	return protoRuntime{
		Paths:            paths,
		Generators:       gens,
		OutputRules:      rules,
		GeneratorsByName: gensByName,
	}, nil
}

// protoRuntime represents the raw pieces needed to compose a runtime, as
// parsed from some options.
type protoRuntime struct {
	Paths            []string
	Generators       Generators
	OutputRules      OutputRules
	GeneratorsByName map[string]*Generator
}

// splitOutputRuleOption splits a marker name of "output:rule:gen" or "output:rule"
// into its compontent rule and generator name.
func splitOutputRuleOption(name string) (ruleName string, genName string) {
	parts := strings.SplitN(name, ":", 3)
	if len(parts) == 3 {
		// output:<generator>:<rule>
		return parts[2], parts[1]
	}
	// output:<rule>
	return parts[1], ""
}
