// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"github.com/cilium/cilium/api/v1/flow"
)

// TraceParent tracks trace parent information.
type TraceParent struct {
	TraceID string `json:"trace_id,omitempty"`
}

// IsEmpty returns true if target has no data.
func (t TraceParent) IsEmpty() bool {
	return t.TraceID == ""
}

// TraceContext tracks trace context information.
type TraceContext struct {
	Parent TraceParent `json:"parent,omitempty"`
}

// IsEmpty returns true if target has no data.
func (t TraceContext) IsEmpty() bool {
	return t.Parent.IsEmpty()
}

func (t TraceContext) toProto() *flow.TraceContext {
	if t.IsEmpty() {
		return nil
	}

	return &flow.TraceContext{
		Parent: &flow.TraceParent{
			TraceId: t.Parent.TraceID,
		},
	}
}

// ProtoToTraceContext converts a protobuf TraceContext to an internal shape.
func ProtoToTraceContext(t *flow.TraceContext) TraceContext {
	if t == nil {
		return TraceContext{}
	}
	return TraceContext{
		Parent: TraceParent{
			TraceID: t.Parent.TraceId,
		},
	}
}
