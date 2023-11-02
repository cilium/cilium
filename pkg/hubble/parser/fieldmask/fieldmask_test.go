// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

//nolint:govet
package fieldmask

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestFieldMask_invalid(t *testing.T) {
	fm, err := New(&fieldmaskpb.FieldMask{Paths: []string{"invalid-path"}})
	assert.ErrorContains(t, err, "invalid fieldmask")
	assert.False(t, fm.Active())
}

func TestFieldMask_inactive(t *testing.T) {
	fm, err := New(&fieldmaskpb.FieldMask{Paths: []string{}})
	assert.NoError(t, err)
	assert.False(t, fm.Active())
}

func TestFieldMask_normalized_parent(t *testing.T) {
	fm, err := New(&fieldmaskpb.FieldMask{Paths: []string{"source", "source.identity", "source", "source.pod_name"}})
	assert.NoError(t, err)
	assert.Len(t, fm, 1)
	assert.Len(t, fm["source"], 0)
	assert.True(t, fm.Active())
}

func TestFieldMask_normalized_child(t *testing.T) {
	fm, err := New(&fieldmaskpb.FieldMask{Paths: []string{"source.identity", "source.identity", "source.pod_name"}})
	assert.NoError(t, err)
	assert.Len(t, fm, 1)
	assert.Len(t, fm["source"], 2)
	assert.True(t, fm.Active())
}

func TestFieldMask_copy_with_alloc(t *testing.T) {
	fm, err := New(&fieldmaskpb.FieldMask{Paths: []string{"source.identity", "source.pod_name", "destination"}})
	assert.NoError(t, err)
	assert.True(t, fm.Active())

	flow := &flowpb.Flow{}
	fm.Alloc(flow.ProtoReflect())

	srcA := &flowpb.Flow{
		NodeName:    "srcA",
		Source:      &flowpb.Endpoint{ID: 1234, PodName: "podA", Namespace: "nsA"},
		Destination: &flowpb.Endpoint{ID: 5678, PodName: "podB", Namespace: "nsB", Identity: 9123},
	}
	srcACopy := proto.Clone(srcA).(*flowpb.Flow)

	fm.Copy(flow.ProtoReflect(), srcA.ProtoReflect())
	// Confirm that source flow wasn't modified
	assert.True(t, assert.ObjectsExportedFieldsAreEqual(srcACopy, srcA),
		"expected exported flow fields to be equal")

	assert.True(t, assert.ObjectsExportedFieldsAreEqual(&flowpb.Flow{
		Source:      &flowpb.Endpoint{PodName: "podA"},
		Destination: &flowpb.Endpoint{ID: 5678, PodName: "podB", Namespace: "nsB", Identity: 9123},
	}, flow), "expected exported flow fields to be equal")

	// Set a new field and confirm that previous values were cleared.
	srcB := &flowpb.Flow{
		NodeName:    "srcB",
		Source:      &flowpb.Endpoint{Identity: 1234},
		Destination: &flowpb.Endpoint{Namespace: "nsA", Identity: 0234},
	}
	fm.Copy(flow.ProtoReflect(), srcB.ProtoReflect())
	assert.True(t, assert.ObjectsExportedFieldsAreEqual(&flowpb.Flow{
		Source:      &flowpb.Endpoint{Identity: 1234},
		Destination: &flowpb.Endpoint{Namespace: "nsA", Identity: 0234},
	}, flow), "expected exported flow fields to be equal")
}

func TestFieldMask_copy_without_alloc(t *testing.T) {
	fm, err := New(&fieldmaskpb.FieldMask{Paths: []string{"source.identity", "source.pod_name", "destination"}})
	assert.NoError(t, err)
	assert.True(t, fm.Active())

	flow := &flowpb.Flow{}

	srcA := &flowpb.Flow{
		NodeName:    "srcA",
		Source:      &flowpb.Endpoint{ID: 1234, PodName: "podA", Namespace: "nsA"},
		Destination: &flowpb.Endpoint{ID: 5678, PodName: "podB", Namespace: "nsB", Identity: 9123},
	}

	// Allocate field when not pre-allocated
	assert.NotPanics(t, func() { fm.Copy(flow.ProtoReflect(), srcA.ProtoReflect()) })
	assert.True(t, assert.ObjectsExportedFieldsAreEqual(&flowpb.Flow{
		Source:      &flowpb.Endpoint{PodName: "podA"},
		Destination: &flowpb.Endpoint{ID: 5678, PodName: "podB", Namespace: "nsB", Identity: 9123},
	}, flow), "expected exported flow fields to be equal")
}
