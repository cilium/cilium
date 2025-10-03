// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package fieldaggregate

import (
	"fmt"
	"sort"

	"github.com/cilium/cilium/pkg/hubble/parser/fieldmask"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// FieldAggregate wraps a FieldMask to provide aggregation-specific functionality
// This avoids code duplication by reusing the existing FieldMask implementation
type FieldAggregate struct {
	fieldmask.FieldMask
}

// New constructs a FieldAggregate based on validated and normalized field mask
func New(fm *fieldmaskpb.FieldMask) (FieldAggregate, error) {
	if fm == nil {
		return FieldAggregate{}, nil
	}

	mask, err := fieldmask.New(fm)
	if err != nil {
		return FieldAggregate{}, fmt.Errorf("invalid fieldaggregate: %w", err)
	}

	return FieldAggregate{FieldMask: mask}, nil
}

// Len returns the number of top-level fields in the aggregate
func (f FieldAggregate) Len() int {
	return len(f.FieldMask)
}

// Get returns the sub-aggregate for a given field name (for testing purposes)
func (f FieldAggregate) Get(name string) FieldAggregate {
	if subMask, ok := f.FieldMask[name]; ok {
		return FieldAggregate{FieldMask: subMask}
	}
	return FieldAggregate{}
}

// GetFieldPaths extracts all field paths from the FieldAggregate.
// This reconstructs the original dot-notation paths that were used to create the aggregation.
// This is the only method that's unique to FieldAggregate (not in base FieldMask).
func (f FieldAggregate) GetFieldPaths() []string {
	var paths []string
	f.collectPaths("", &paths)
	sort.Strings(paths) // Sort for consistent ordering
	return paths
}

// collectPaths recursively traverses the FieldMask tree to collect all field paths
func (f FieldAggregate) collectPaths(prefix string, paths *[]string) {
	for name, subFields := range f.FieldMask {
		currentPath := name
		if prefix != "" {
			currentPath = prefix + "." + name
		}

		if len(subFields) == 0 {
			// This is a leaf node, add the complete path
			*paths = append(*paths, currentPath)
		} else {
			// This has children, recurse
			FieldAggregate{FieldMask: subFields}.collectPaths(currentPath, paths)
		}
	}
}
