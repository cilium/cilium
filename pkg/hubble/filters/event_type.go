// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

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
		case *flowpb.DebugEvent:
			for _, typeFilter := range types {
				if t := typeFilter.GetType(); t != 0 && t != monitorAPI.MessageTypeDebug {
					continue
				}
				debugEventType := int32(ev.GetDebugEvent().GetType())
				if typeFilter.GetMatchSubType() && typeFilter.GetSubType() != debugEventType {
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
