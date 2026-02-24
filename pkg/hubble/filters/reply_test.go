// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/ir"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func Test_filterByReplyField(t *testing.T) {
	type args struct {
		f  []*flowpb.FlowFilter
		ev *v1.Event
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    bool
	}{
		{
			name: "nil flow",
			args: args{
				f:  []*flowpb.FlowFilter{{Reply: []bool{true}}},
				ev: &v1.Event{},
			},
			want: false,
		},
		{
			name: "empty-param",
			args: args{
				f:  []*flowpb.FlowFilter{{Reply: []bool{}}},
				ev: &v1.Event{Event: &ir.Flow{Reply: ir.ReplyYes}},
			},
			want: true,
		},
		{
			name: "empty-param-2",
			args: args{
				f:  []*flowpb.FlowFilter{{Reply: []bool{}}},
				ev: &v1.Event{Event: &ir.Flow{Reply: ir.ReplyNo}},
			},
			want: true,
		},
		{
			name: "no-reply",
			args: args{
				f:  []*flowpb.FlowFilter{{Reply: []bool{false}}},
				ev: &v1.Event{Event: &ir.Flow{Reply: ir.ReplyNo}},
			},
			want: true,
		},
		{
			name: "trace-event-from-endpoint",
			args: args{
				f: []*flowpb.FlowFilter{{Reply: []bool{false}}},
				ev: &v1.Event{Event: &ir.Flow{
					EventType: ir.EventType{
						Type:    monitorAPI.MessageTypeTrace,
						SubType: monitorAPI.TraceFromLxc,
					},
					Reply: ir.ReplyUnknown,
				}},
			},
			want: false,
		},
		{
			name: "trace-event-to-endpoint",
			args: args{
				f: []*flowpb.FlowFilter{{Reply: []bool{false}}},
				ev: &v1.Event{Event: &ir.Flow{
					EventType: ir.EventType{
						Type:    monitorAPI.MessageTypeTrace,
						SubType: monitorAPI.TraceToLxc,
					},
					Reply: ir.ReplyNo,
				}},
			},
			want: true,
		},
		{
			name: "reply",
			args: args{
				f:  []*flowpb.FlowFilter{{Reply: []bool{true}}},
				ev: &v1.Event{Event: &ir.Flow{Reply: ir.ReplyYes}},
			},
			want: true,
		},
		{
			name: "drop implies reply=false",
			args: args{
				f:  []*flowpb.FlowFilter{{Reply: []bool{false}}},
				ev: &v1.Event{Event: &ir.Flow{Verdict: flowpb.Verdict_DROPPED, Reply: ir.ReplyUnknown}},
			},
			want: true,
		},
		{
			name: "no-match",
			args: args{
				f:  []*flowpb.FlowFilter{{Reply: []bool{true}}},
				ev: &v1.Event{Event: &ir.Flow{Reply: ir.ReplyNo}},
			},
			want: false,
		},
		{
			name: "no-match-2",
			args: args{
				f:  []*flowpb.FlowFilter{{Reply: []bool{false}}},
				ev: &v1.Event{Event: &ir.Flow{Reply: ir.ReplyYes}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(t.Context(), tt.args.f, []OnBuildFilter{&ReplyFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("\"%s\" error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got := fl.MatchOne(tt.args.ev); got != tt.want {
				t.Errorf("\"%s\" got %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
