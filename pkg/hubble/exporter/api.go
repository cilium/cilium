// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"reflect"
	"slices"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/time"
)

// FlowLogExporter exports hubble events to configured target file.
type FlowLogExporter interface {
	observeroption.OnDecodedEvent
	// Stop stops this exporter instance from further events processing.
	Stop() error
}

// FlowFilters is a slice of filters to include or exclude flows.
type FlowFilters []*flowpb.FlowFilter

// FieldMask is a slice of fields that are included in output.
type FieldMask []string

// FlowLogConfig represents configuration of single dynamic exporter.
type FlowLogConfig struct {
	Name           string      `json:"name,omitempty" yaml:"name,omitempty"`
	FilePath       string      `json:"filePath,omitempty" yaml:"filePath,omitempty"`
	FieldMask      FieldMask   `json:"fieldMask,omitempty" yaml:"fieldMask,omitempty"`
	IncludeFilters FlowFilters `json:"includeFilters,omitempty" yaml:"includeFilters,omitempty"`
	ExcludeFilters FlowFilters `json:"excludeFilters,omitempty" yaml:"excludeFilters,omitempty"`
	End            *time.Time  `json:"end,omitempty" yaml:"end,omitempty"`
}

func (f *FlowLogConfig) equals(other *FlowLogConfig) bool {
	if f == nil && other == nil {
		return true
	}
	if f == nil || other == nil {
		return false
	}

	if f.FilePath != other.FilePath {
		return false
	}

	if !f.FieldMask.equals(other.FieldMask) {
		return false
	}

	if !f.IncludeFilters.equals(other.IncludeFilters) {
		return false
	}

	if !f.ExcludeFilters.equals(other.ExcludeFilters) {
		return false
	}

	if f.End == nil && other.End != nil ||
		f.End != nil && other.End == nil ||
		f.End != nil && other.End != nil && !f.End.Equal(*other.End) {
		return false
	}

	return true
}

func (f FlowFilters) equals(other FlowFilters) bool {
	aFiltersSet, bFiltersSet := make(map[string]bool), make(map[string]bool)

	for _, filter := range f {
		aFiltersSet[filter.String()] = true
	}
	for _, filter := range other {
		bFiltersSet[filter.String()] = true
	}
	return reflect.DeepEqual(aFiltersSet, bFiltersSet)
}

func (f FieldMask) equals(other FieldMask) bool {
	slices.Sort(f)
	slices.Sort(other)
	return reflect.DeepEqual(f, other)
}

// DynamicExportersConfig represents structure of dynamic hubble exporters
// configuration file.
type DynamicExportersConfig struct {
	FlowLogs []*FlowLogConfig `json:"flowLogs,omitempty" yaml:"flowLogs,omitempty"`
}
