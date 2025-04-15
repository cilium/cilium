// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package exportercell

import (
	"fmt"
	"maps"
	"slices"

	"github.com/cilium/cilium/pkg/hubble/exporter"
)

// FlowLogExporterBuilder knows how to build a FlowLog The Replaces field
// indicate that an existing builder with a matching Name field should be
// replaced by this one.
type FlowLogExporterBuilder struct {
	Name     string
	Replaces string
	Build    func() (exporter.FlowLogExporter, error)
}

// resolveExporters verifies the slice of builders for duplicates and performs
// replace operations as needed before building and returning the resulting
// FlowLogExporters.
//
// This function panics if two or more builders have the same name or a
// Replaces target builder was not found.
func ResolveExporters(builders []*FlowLogExporterBuilder) ([]exporter.FlowLogExporter, error) {
	builders, err := replaceBuilders(builders)
	if err != nil {
		// if we reach here, we got an implementation bug since we manage builders in code
		panic(fmt.Sprintf("cannot resolve flow exporter: %s", err))
	}
	return buildExporters(builders)
}

func replaceBuilders(builders []*FlowLogExporterBuilder) ([]*FlowLogExporterBuilder, error) {
	buildersByName := make(map[string]*FlowLogExporterBuilder, len(builders))
	for _, builder := range builders {
		if builder.Name == "" {
			return nil, fmt.Errorf("exporter builder name not set")
		}
		if _, ok := buildersByName[builder.Name]; ok {
			return nil, fmt.Errorf("exporter builder %q already exists", builder.Name)
		}
		buildersByName[builder.Name] = builder
	}
	for _, builder := range builders {
		if builder.Replaces == "" {
			continue
		}
		if builder.Replaces == builder.Name {
			continue
		}
		delete(buildersByName, builder.Replaces)
		buildersByName[builder.Name] = builder
	}
	return slices.Collect(maps.Values(buildersByName)), nil
}

func buildExporters(builders []*FlowLogExporterBuilder) ([]exporter.FlowLogExporter, error) {
	exporters := make([]exporter.FlowLogExporter, 0, len(builders))
	for _, builder := range builders {
		exp, err := builder.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build hubble exporter %q: %w", builder.Name, err)
		}
		if exp != nil {
			exporters = append(exporters, exp)
		}
	}
	return exporters, nil
}
