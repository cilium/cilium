// Copyright 2020 Authors of Cilium
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

// +build !privileged_tests

package filters

import (
	"context"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func TestEventTypeFilter(t *testing.T) {
	type args struct {
		f  []*flowpb.FlowFilter
		ev []*v1.Event
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    []bool
	}{
		{
			name: "drop without subtype",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						EventType: []*flowpb.EventTypeFilter{
							{
								Type: monitorAPI.MessageTypeDrop,
							},
						},
					},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{}},
					{Event: &flowpb.Flow{EventType: &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeDrop}}},
					{Event: &flowpb.Flow{EventType: &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeDrop, SubType: 2}}},
					{Event: &flowpb.Flow{EventType: &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeCapture}}},
					{Event: &flowpb.AgentEvent{}},
					{Event: &flowpb.LostEvent{}},
				},
			},
			want: []bool{
				false,
				true,
				true,
				false,
				false,
				true, // always want lost events
			},
		},
		{
			name: "drop with subtype",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						EventType: []*flowpb.EventTypeFilter{
							{
								Type:         monitorAPI.MessageTypeDrop,
								MatchSubType: true,
								SubType:      2, // invalid packet
							},
						},
					},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{}},
					{Event: &flowpb.Flow{EventType: &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeDrop}}},
					{Event: &flowpb.Flow{EventType: &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeDrop, SubType: 2}}},
					{Event: &flowpb.Flow{EventType: &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeCapture}}},
					{Event: &flowpb.AgentEvent{}},
					{Event: &flowpb.LostEvent{}},
				},
			},
			want: []bool{
				false,
				false,
				true,
				false,
				false,
				true, // always want lost events
			},
		},
		{
			name: "agent event without subtype",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						EventType: []*flowpb.EventTypeFilter{
							{
								Type: monitorAPI.MessageTypeAgent,
							},
						},
					},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{}},
					{Event: &flowpb.Flow{EventType: &flowpb.CiliumEventType{}}},
					{Event: &flowpb.AgentEvent{}},
					{Event: &flowpb.AgentEvent{Type: flowpb.AgentEventType_ENDPOINT_CREATED}},
					{Event: &flowpb.AgentEvent{Type: flowpb.AgentEventType_IPCACHE_UPSERTED}},
					{Event: &flowpb.LostEvent{}},
				},
			},
			want: []bool{
				false,
				false,
				true,
				true,
				true,
				true, // always want lost events
			},
		},
		{
			name: "agent event with subtype",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						EventType: []*flowpb.EventTypeFilter{
							{
								Type:         monitorAPI.MessageTypeAgent,
								MatchSubType: true,
								SubType:      int32(monitorAPI.AgentNotifyEndpointCreated),
							},
						},
					},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{}},
					{Event: &flowpb.Flow{EventType: &flowpb.CiliumEventType{}}},
					{Event: &flowpb.Flow{EventType: &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeAccessLog}}},
					{Event: &flowpb.AgentEvent{}},
					{Event: &flowpb.AgentEvent{Type: flowpb.AgentEventType_ENDPOINT_CREATED}},
					{Event: &flowpb.AgentEvent{Type: flowpb.AgentEventType_POLICY_DELETED}},
					{Event: &flowpb.LostEvent{}},
				},
			},
			want: []bool{
				false,
				false,
				false,
				false,
				true,
				false,
				true, // always want lost events
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&EventTypeFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildFilterList() with EventTypeFilter: error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i, ev := range tt.args.ev {
				if filterResult := fl.MatchOne(ev); filterResult != tt.want[i] {
					t.Errorf("for event %d (%v) got %v, want %v", i, ev, filterResult, tt.want[i])
				}
			}
		})
	}
}
