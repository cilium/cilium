// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

//nolint:govet
package fieldmask

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
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
	assert.Empty(t, fm["source"])
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
	assert.True(t, assert.EqualExportedValues(t, srcACopy, srcA),
		"expected exported flow fields to be equal")

	assert.True(t, assert.EqualExportedValues(t, &flowpb.Flow{
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
	assert.True(t, assert.EqualExportedValues(t, &flowpb.Flow{
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
	assert.True(t, assert.EqualExportedValues(t, &flowpb.Flow{
		Source:      &flowpb.Endpoint{PodName: "podA"},
		Destination: &flowpb.Endpoint{ID: 5678, PodName: "podB", Namespace: "nsB", Identity: 9123},
	}, flow), "expected exported flow fields to be equal")
}

func TestFieldMask_oneof_multiple_variants(t *testing.T) {
	// Test that specifying multiple oneof variants only copies the active one.
	fm, err := New(&fieldmaskpb.FieldMask{Paths: []string{
		"source.namespace",
		"l4.TCP.destination_port",
		"l4.UDP.destination_port",
		"l7.http.code",
		"l7.dns.rcode",
	}})
	assert.NoError(t, err)
	assert.True(t, fm.Active())

	// Source flow has TCP and HTTP (not UDP or DNS).
	srcFlow := &flowpb.Flow{
		Source: &flowpb.Endpoint{Namespace: "default"},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					SourcePort:      33001,
					DestinationPort: 443,
				},
			},
		},
		L7: &flowpb.Layer7{
			Type: flowpb.L7FlowType_RESPONSE,
			Record: &flowpb.Layer7_Http{
				Http: &flowpb.HTTP{
					Code: 200,
				},
			},
		},
	}

	dstFlow := &flowpb.Flow{}
	fm.Copy(dstFlow.ProtoReflect(), srcFlow.ProtoReflect())

	// Should only copy TCP (not UDP) and HTTP (not DNS).
	assert.NotNil(t, dstFlow.L4, "L4 should be set")
	assert.IsType(t, &flowpb.Layer4_TCP{}, dstFlow.L4.Protocol, "Should have TCP protocol, not UDP")
	assert.Equal(t, uint32(443), dstFlow.L4.GetTCP().GetDestinationPort(), "TCP destination port should be 443")
	assert.Equal(t, uint32(0), dstFlow.L4.GetTCP().GetSourcePort(), "TCP source port should be 0 (not in mask)")

	assert.NotNil(t, dstFlow.L7, "L7 should be set")
	assert.IsType(t, &flowpb.Layer7_Http{}, dstFlow.L7.Record, "Should have HTTP record, not DNS")
	assert.Equal(t, uint32(200), dstFlow.L7.GetHttp().GetCode(), "HTTP code should be 200")

	// Verify no spurious UDP or DNS created.
	assert.Nil(t, dstFlow.L4.GetUDP(), "Should not have UDP structure")
	assert.Nil(t, dstFlow.L7.GetDns(), "Should not have DNS structure")
}

func TestFieldMask_nested_vs_parent_only(t *testing.T) {
	// Test the difference between specifying nested properties vs parent-only fields:
	// - Nested property (e.g., "source.namespace") creates empty object when not present
	// - Parent-only (e.g., "l4") results in nil when not present
	fm, err := New(&fieldmaskpb.FieldMask{Paths: []string{
		"source.namespace",
		"l4",
	}})
	assert.NoError(t, err)

	srcFlow := &flowpb.Flow{
		// No Source, No L4
		Destination: &flowpb.Endpoint{
			PodName: "test",
		},
	}

	dstFlow := &flowpb.Flow{}
	fm.Copy(dstFlow.ProtoReflect(), srcFlow.ProtoReflect())

	// Source is not nil because "source.namespace" (nested property) was specified.
	assert.NotNil(t, dstFlow.Source, "Source should be allocated when nested property specified")
	assert.Empty(t, dstFlow.Source.Namespace, "Source namespace should be empty")

	// L4 is nil because "l4" was specified without nested properties.
	assert.Nil(t, dstFlow.L4, "L4 should be nil when parent specified without nested properties")
}
