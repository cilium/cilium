// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/monitor/api"
)

// EventType tracks flow event type and subtype.
type EventType struct {
	Type    int32 `json:"type,omitempty"`
	SubType int32 `json:"subType,omitempty"`
}

// IsEmpty returns true if the event type is unspecified.
func (e EventType) IsEmpty() bool {
	return e.Type == api.MessageTypeUnspec && e.SubType == api.MessageTypeUnspec
}

func (e EventType) toProto() *flow.CiliumEventType {
	if e.IsEmpty() {
		return nil
	}

	return &flow.CiliumEventType{
		Type:    e.Type,
		SubType: e.SubType,
	}
}

// ProtoToEventType converts protobuf event type to its internal representation.
func ProtoToEventType(e *flow.CiliumEventType) EventType {
	if e == nil {
		return EventType{}
	}

	return EventType{
		Type:    e.Type,
		SubType: e.SubType,
	}
}
