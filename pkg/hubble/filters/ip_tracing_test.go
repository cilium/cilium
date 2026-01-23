// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestIPTraceIDFilter(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		f    []*flowpb.FlowFilter
		ev   *v1.Event
		want bool
	}{
		{
			name: "match_single_filter",
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{1}},
			},
			ev: &v1.Event{
				Event: &flowpb.Flow{
					IpTraceId: &flowpb.IPTraceID{
						TraceId: 1,
					},
				},
			},
			want: true,
		},
		{
			name: "match_multiple_filters",
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{1}},
				{IpTraceId: []uint64{2}},
			},
			ev: &v1.Event{
				Event: &flowpb.Flow{
					IpTraceId: &flowpb.IPTraceID{
						TraceId: 2,
					},
				},
			},
			want: true,
		},
		{
			name: "no_filter",
			ev: &v1.Event{
				Event: &flowpb.Flow{
					IpTraceId: &flowpb.IPTraceID{
						TraceId: 1,
					},
				},
			},
			want: true,
		},
		{
			name: "mismatch",
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{1}},
			},
			ev: &v1.Event{
				Event: &flowpb.Flow{
					IpTraceId: &flowpb.IPTraceID{
						TraceId: 2,
					},
				},
			},
			want: false,
		},
		{
			name: "no_trace_id",
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{1}},
			},
			ev: &v1.Event{
				Event: &flowpb.Flow{},
			},
			want: false,
		},
		{
			name: "option_match",
			f: []*flowpb.FlowFilter{
				{IpTraceOption: []uint32{100}},
			},
			ev: &v1.Event{
				Event: &flowpb.Flow{
					IpTraceId: &flowpb.IPTraceID{
						TraceId:      123,
						IpOptionType: 100,
					},
				},
			},
			want: true,
		},
		{
			name: "option_mismatch",
			f: []*flowpb.FlowFilter{
				{IpTraceOption: []uint32{100}},
			},
			ev: &v1.Event{
				Event: &flowpb.Flow{
					IpTraceId: &flowpb.IPTraceID{
						TraceId:      123,
						IpOptionType: 200,
					},
				},
			},
			want: false,
		},
		{
			name: "option_match_but_no_trace_id",
			f: []*flowpb.FlowFilter{
				{IpTraceOption: []uint32{100}},
			},
			ev: &v1.Event{
				Event: &flowpb.Flow{
					IpTraceId: &flowpb.IPTraceID{
						IpOptionType: 100,
					},
				},
			},
			want: false,
		},
		{
			name: "option_match_trace_id_zero",
			f: []*flowpb.FlowFilter{
				{IpTraceOption: []uint32{100}},
			},
			ev: &v1.Event{
				Event: &flowpb.Flow{
					IpTraceId: &flowpb.IPTraceID{
						TraceId:      0,
						IpOptionType: 100,
					},
				},
			},
			want: false,
		},
		{
			name: "option_and_id_match",
			f: []*flowpb.FlowFilter{
				{
					IpTraceId:     []uint64{123},
					IpTraceOption: []uint32{100},
				},
			},
			ev: &v1.Event{
				Event: &flowpb.Flow{
					IpTraceId: &flowpb.IPTraceID{
						TraceId:      123,
						IpOptionType: 100,
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(ctx, tt.f, []OnBuildFilter{&IPTraceIDFilter{}})
			if err != nil {
				t.Fatalf("Faile to build filter: %v", err)
			}
			assert.Equal(t, tt.want, fl.MatchOne(tt.ev))
		})
	}
}
