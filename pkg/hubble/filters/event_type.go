// Copyright 2019-2020 Authors of Hubble
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

package filters

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func filterByEventType(types []*flowpb.EventTypeFilter) FilterFunc {
	return func(ev *v1.Event) bool {
		switch ev.Event.(type) {
		case *flowpb.Flow:
			event := ev.GetFlow().GetEventType()
			if event == nil {
				return false
			}
			for _, typeFilter := range types {
				if t := typeFilter.GetType(); t != 0 && event.Type != t {
					continue
				}
				if typeFilter.GetMatchSubType() && typeFilter.GetSubType() != event.SubType {
					continue
				}
				return true
			}
		case *flowpb.AgentEvent:
			for _, typeFilter := range types {
				if t := typeFilter.GetType(); t != 0 && t != monitorAPI.MessageTypeAgent {
					continue
				}
				agentEventType := int32(ev.GetAgentEvent().GetType())
				if typeFilter.GetMatchSubType() && typeFilter.GetSubType() != agentEventType {
					continue
				}
				return true
			}
		case *flowpb.LostEvent:
			// Currently there's no way in the Hubble CLI and API to filter lost events,
			// thus always include them. They are very uncommon and only occur on
			// overloaded systems, in which case a user would anyway want to get them.
			return true
		}

		return false
	}
}

// EventTypeFilter implements filtering based on event type
type EventTypeFilter struct{}

// OnBuildFilter builds an event type filter
func (e *EventTypeFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	types := ff.GetEventType()
	if len(types) > 0 {
		fs = append(fs, filterByEventType(types))
	}

	return fs, nil
}
