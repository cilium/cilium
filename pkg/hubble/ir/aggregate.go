// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// Aggregate tracks aggregate flow information.
type Aggregate struct {
	IngressFlowCount          uint32 `json:"ingress_flow_count,omitempty"`
	EgressFlowCount           uint32 `json:"egress_flow_count,omitempty"`
	UnknownDirectionFlowCount uint32 `json:"unknown_direction_flow_count,omitempty"`
}

// IsEmpty returns true if target has no data.
func (a Aggregate) IsEmpty() bool {
	return a.IngressFlowCount == 0 && a.EgressFlowCount == 0 && a.UnknownDirectionFlowCount == 0
}

func (a Aggregate) toProto() *flowpb.Aggregate {
	if a.IsEmpty() {
		return nil
	}
	return &flowpb.Aggregate{
		IngressFlowCount:          a.IngressFlowCount,
		EgressFlowCount:           a.EgressFlowCount,
		UnknownDirectionFlowCount: a.UnknownDirectionFlowCount,
	}
}

// ProtoToAggregate converts protobuf.Aggregate to an IR aggregate.
func ProtoToAggregate(a *flowpb.Aggregate) Aggregate {
	if a == nil {
		return Aggregate{}
	}

	return Aggregate{
		IngressFlowCount:          a.GetIngressFlowCount(),
		EgressFlowCount:           a.GetEgressFlowCount(),
		UnknownDirectionFlowCount: a.GetUnknownDirectionFlowCount(),
	}
}
