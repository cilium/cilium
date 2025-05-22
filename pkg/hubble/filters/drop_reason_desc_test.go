// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestDropReasonDescFilter(t *testing.T) {
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
			name: "drop with verdict",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DropReasonDesc: []flowpb.DropReason{
							flowpb.DropReason_UNSUPPORTED_L3_PROTOCOL,
							flowpb.DropReason_POLICY_DENIED,
						},
					},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{}},
					{Event: &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED, DropReasonDesc: flowpb.DropReason_UNSUPPORTED_L3_PROTOCOL}},
					{Event: &flowpb.Flow{Verdict: flowpb.Verdict_VERDICT_UNKNOWN, DropReasonDesc: flowpb.DropReason_INVALID_SOURCE_IP}},
					{Event: &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED, DropReasonDesc: flowpb.DropReason_POLICY_DENIED}},
					{Event: &flowpb.AgentEvent{}},
					{Event: &flowpb.LostEvent{}},
				},
			},
			want: []bool{
				false,
				true,
				false,
				true,
				false,
				false,
			},
		},
		{
			name: "drop without verdict",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DropReasonDesc: []flowpb.DropReason{flowpb.DropReason_UNSUPPORTED_L3_PROTOCOL},
					},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{}},
					{Event: &flowpb.Flow{Verdict: flowpb.Verdict_VERDICT_UNKNOWN, DropReasonDesc: flowpb.DropReason_UNSUPPORTED_L3_PROTOCOL}},
					{Event: &flowpb.Flow{Verdict: flowpb.Verdict_VERDICT_UNKNOWN, DropReasonDesc: flowpb.DropReason_INVALID_SOURCE_IP}},
					{Event: &flowpb.AgentEvent{}},
					{Event: &flowpb.LostEvent{}},
				},
			},
			want: []bool{
				false,
				false,
				false,
				false,
				false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(t.Context(), tt.args.f, []OnBuildFilter{&DropReasonDescFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildFilterList() with DropReasonDescFilter: error = %v, wantErr %v", err, tt.wantErr)
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
