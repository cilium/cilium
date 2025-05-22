// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	"github.com/cilium/hive/hivetest"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestCELExpressionFilter(t *testing.T) {
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
			name: "verdict",
			args: args{
				f: []*flowpb.FlowFilter{
					{Experimental: &flowpb.FlowFilter_Experimental{CelExpression: []string{"_flow.verdict == Verdict.FORWARDED || _flow.verdict == Verdict.TRANSLATED"}}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED}},
					{Event: &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED}},
					{Event: &flowpb.Flow{Verdict: flowpb.Verdict_TRANSLATED}},
				},
			},
			want: []bool{
				true,
				false,
				true,
			},
		},
		{
			name: "ip",
			args: args{
				f: []*flowpb.FlowFilter{
					{Experimental: &flowpb.FlowFilter_Experimental{CelExpression: []string{"_flow.IP.source == '1.1.1.1' || _flow.IP.destination == '8.8.8.8'"}}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "1.1.1.1", Destination: "10.0.0.2"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "10.0.0.2", Destination: "1.1.1.1"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "10.0.0.2", Destination: "8.8.8.8"}}},
				},
			},
			want: []bool{
				true,
				false,
				true,
			},
		},
		{
			name: "l4 protocol",
			args: args{
				f: []*flowpb.FlowFilter{
					{Experimental: &flowpb.FlowFilter_Experimental{CelExpression: []string{"has(_flow.l4.TCP)"}}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{SourcePort: 20222, DestinationPort: 80}}}}},
					{Event: &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{SourcePort: 30222, DestinationPort: 53}}}}},
					{Event: &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{SourcePort: 20222, DestinationPort: 443}}}}},
				},
			},
			want: []bool{
				true,
				false,
				true,
			},
		},
		{
			name: "l4 protocol port",
			args: args{
				f: []*flowpb.FlowFilter{
					{Experimental: &flowpb.FlowFilter_Experimental{CelExpression: []string{"has(_flow.l4.TCP) && (_flow.l4.TCP.destination_port == uint(80) || _flow.l4.TCP.destination_port == uint(443))"}}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{SourcePort: 20222, DestinationPort: 80}}}}},
					{Event: &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{SourcePort: 30222, DestinationPort: 53}}}}},
					{Event: &flowpb.Flow{L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{SourcePort: 20222, DestinationPort: 443}}}}},
				},
			},
			want: []bool{
				true,
				false,
				true,
			},
		},
		{
			name: "invalid expression",
			args: args{
				f: []*flowpb.FlowFilter{
					{Experimental: &flowpb.FlowFilter_Experimental{CelExpression: []string{"something-invalid"}}},
				},
			},
			wantErr: true,
		},
		{
			name: "non-boolean expression",
			args: args{
				f: []*flowpb.FlowFilter{
					{Experimental: &flowpb.FlowFilter_Experimental{CelExpression: []string{"_flow"}}},
				},
			},
			wantErr: true,
		},
		{
			name: "empty expression",
			args: args{
				f: []*flowpb.FlowFilter{
					{Experimental: &flowpb.FlowFilter_Experimental{CelExpression: []string{""}}},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := hivetest.Logger(t)
			fl, err := BuildFilterList(t.Context(), tt.args.f, []OnBuildFilter{&CELExpressionFilter{log: log}})
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i, ev := range tt.args.ev {
				if filterResult := fl.MatchOne(ev); filterResult != tt.want[i] {
					t.Errorf("filterResult %d = %v, want %v", i, filterResult, tt.want[i])
				}
			}
		})
	}
}
