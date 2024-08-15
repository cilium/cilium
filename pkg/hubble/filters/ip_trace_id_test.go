// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble
package filters

import (
	"context"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestIPTraceIDFilter(t *testing.T) {
	// Testing basic functionality
	tests := []struct {
		name    string
		f       []*flowpb.FlowFilter
		ev      []*v1.Event
		wantErr bool
		want    []bool
	}{
		{
			name: "single trace ID",
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{0x1234}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x1234, IpOptionType: 136}}},
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x5678, IpOptionType: 136}}},
			},
			want: []bool{
				true,
				false,
			},
		},
		{
			name: "single 4-byte trace ID",
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{0x12345678}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x12345678, IpOptionType: 136}}},
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x56781234, IpOptionType: 136}}},
			},
			want: []bool{
				true,
				false,
			},
		},
		{
			name: "single 8-byte trace ID",
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{0x123456789ABCDEF0}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x123456789ABCDEF0, IpOptionType: 136}}},
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x56781234ABCDEF00, IpOptionType: 136}}},
			},
			want: []bool{
				true,
				false,
			},
		},
		{
			name: "multiple trace IDs",
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{0x1234, 0x5678}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x1234, IpOptionType: 136}}},
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x5678, IpOptionType: 136}}},
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x1111, IpOptionType: 136}}},
			},
			want: []bool{
				true,
				true,
				false,
			},
		},
		{
			name: "no trace ID",
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{0x1234}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x5678, IpOptionType: 136}}},
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x1111, IpOptionType: 136}}},
			},
			want: []bool{
				false,
				false,
			},
		},
		{
			name: "leading 0s", // make sure it doesn't crash
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{0x1234}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x0000000000001234, IpOptionType: 136}}},
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x1234, IpOptionType: 136}}},
			},
			want: []bool{
				true,
				true,
			},
		},
		{
			name: "no trace ID in event",
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{0x1234}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{IpTraceId: nil}},
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x5678, IpOptionType: 136}}},
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x1234, IpOptionType: 136}}},
			},
			want: []bool{
				false,
				false,
				true,
			},
		},
		{
			name: "matchall filter", // make sure it doesn't crash
			f: []*flowpb.FlowFilter{
				{
					IpTraceId: []uint64{},
				},
			},
			ev: []*v1.Event{
				{
					Event: &flowpb.Flow{
						IpTraceId: &flowpb.IPTraceID{
							TraceId:      0x1234,
							IpOptionType: 0,
						},
					},
				},
				{
					Event: &flowpb.Flow{
						IpTraceId: &flowpb.IPTraceID{
							TraceId:      0x5678,
							IpOptionType: 0,
						},
					},
				},
				{
					Event: &flowpb.Flow{
						IpTraceId: &flowpb.IPTraceID{
							TraceId:      0x9abc,
							IpOptionType: 0,
						},
					},
				},
			},
			want: []bool{
				true,
				true,
				true,
			},
		},
		{
			name: "nil IPTraceID in event", // make sure it doesn't crash
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{0x1234}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{IpTraceId: nil}},
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x1234, IpOptionType: 136}}},
			},
			want: []bool{
				false,
				true,
			},
		},
		{
			name: "Zero IPTraceID in event", // make sure it doesn't crash
			f: []*flowpb.FlowFilter{
				{IpTraceId: []uint64{0x1234}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0, IpOptionType: 136}}},
				{Event: &flowpb.Flow{IpTraceId: &flowpb.IPTraceID{TraceId: 0x1234, IpOptionType: 136}}},
			},
			want: []bool{
				false,
				true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.f, []OnBuildFilter{&IPTraceIDFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildFilterList() error = %v, wantErr %t", err, tt.wantErr)
				return
			}
			for i, ev := range tt.ev {
				if filterResult := fl.MatchOne(ev); filterResult != tt.want[i] {
					t.Errorf("%q filterResult %d = %t, want %t", tt.name, i, filterResult, tt.want[i])
				}
			}
		})
	}
}
