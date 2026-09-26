// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import "github.com/cilium/cilium/api/v1/flow"

// IPTraceID tracks flow trace ID.
type IPTraceID struct {
	TraceID      uint64 `json:"traceId,omitempty"`
	IPOptionType uint32 `json:"ipOptionType,omitempty"`
}

// IsEmpty returns true if target has no data.
func (t IPTraceID) IsEmpty() bool {
	return t.TraceID == 0 && t.IPOptionType == 0
}

func (t IPTraceID) toProto() *flow.IPTraceID {
	if t.IsEmpty() {
		return nil
	}

	return &flow.IPTraceID{
		TraceId:      t.TraceID,
		IpOptionType: t.IPOptionType,
	}
}

// ProtoToIPTraceID converts a protobuf trace to an internal shape.
func ProtoToIPTraceID(t *flow.IPTraceID) IPTraceID {
	if t == nil {
		return IPTraceID{}
	}

	return IPTraceID{
		TraceID:      t.TraceId,
		IPOptionType: t.IpOptionType,
	}
}
