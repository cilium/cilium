// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	pb "github.com/cilium/cilium/api/v1/flow"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// Event represents a single event observed and stored by Hubble
type Event struct {
	// Timestamp when event was observed in Hubble
	Timestamp *timestamppb.Timestamp
	// Event contains the actual event
	Event interface{}
}

// GetFlow returns the decoded flow, or nil if the event is nil or not a flow
func (ev *Event) GetFlow() *pb.Flow {
	if ev == nil || ev.Event == nil {
		return nil
	}
	if f, ok := ev.Event.(*pb.Flow); ok {
		return f
	}
	return nil
}

// GetAgentEvent returns the decoded agent event, or nil if the event is nil
// or not an agent event
func (ev *Event) GetAgentEvent() *pb.AgentEvent {
	if ev == nil || ev.Event == nil {
		return nil
	}
	if f, ok := ev.Event.(*pb.AgentEvent); ok {
		return f
	}
	return nil
}

// GetDebugEvent returns the decoded debug event, or nil if the event is nil
// or not an debug event
func (ev *Event) GetDebugEvent() *pb.DebugEvent {
	if ev == nil || ev.Event == nil {
		return nil
	}
	if d, ok := ev.Event.(*pb.DebugEvent); ok {
		return d
	}
	return nil
}

// GetLostEvent returns the decoded lost event, or nil if the event is nil
// or not a lost event
func (ev *Event) GetLostEvent() *pb.LostEvent {
	if ev == nil || ev.Event == nil {
		return nil
	}
	if f, ok := ev.Event.(*pb.LostEvent); ok {
		return f
	}
	return nil
}
