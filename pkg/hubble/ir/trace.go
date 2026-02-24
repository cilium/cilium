// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"github.com/cilium/cilium/api/v1/flow"
)

// TraceParent tracks trace parent information.
type TraceParent struct {
	TraceID string `json:"traceId,omitempty"`
}

func (t TraceParent) isEmpty() bool {
	return t.TraceID == ""
}

// TraceContext tracks trace context information.
type TraceContext struct {
	Parent TraceParent `json:"parent,omitempty"`
}

func (t TraceContext) isEmpty() bool {
	return t.Parent.isEmpty()
}

func (t TraceContext) toProto() *flow.TraceContext {
	if t.isEmpty() {
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
