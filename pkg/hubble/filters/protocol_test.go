// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestFlowProtocolFilter(t *testing.T) {
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
			name: "udp",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"udp"}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{}}},
				}},
			},
			want: true,
		},
		{
			name: "http",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"http"}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{}}},
					L7: &flowpb.Layer7{Record: &flowpb.Layer7_Http{Http: &flowpb.HTTP{}}},
				}},
			},
			want: true,
		},
		{
			name: "icmp (v4)",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"icmp"}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_ICMPv4{ICMPv4: &flowpb.ICMPv4{}}},
				}},
			},
			want: true,
		},
		{
			name: "icmp (v6)",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"icmp"}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_ICMPv6{ICMPv6: &flowpb.ICMPv6{}}},
				}},
			},
			want: true,
		},
		{
			name: "multiple protocols",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"tcp", "kafka"}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{}}},
				}},
			},
			want: true,
		},
		{
			name: "invalid protocols",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"not a protocol"}}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&ProtocolFilter{}})
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
