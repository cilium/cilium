// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package fieldaggregate

import (
	"fmt"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/cilium/cilium/pkg/hubble/parser/fieldmask"
)

// FieldAggregate wraps a FieldMask to provide aggregation-specific functionality.
// This avoids code duplication by reusing the existing FieldMask implementation.
type FieldAggregate struct {
	fieldmask.FieldMask
}

// New constructs a FieldAggregate based on validated and normalized field mask.
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

// Len returns the number of top-level fields in the aggregate.
func (f FieldAggregate) Len() int {
	return len(f.FieldMask)
}

// Get returns the sub-aggregate for a given field name (for testing purposes).
func (f FieldAggregate) Get(name string) FieldAggregate {
	if subMask, ok := f.FieldMask[name]; ok {
		return FieldAggregate{FieldMask: subMask}
	}
	return FieldAggregate{}
}
