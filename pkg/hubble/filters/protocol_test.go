// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/ir"
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
				ev: &v1.Event{Event: &ir.Flow{
					L4: ir.Layer4{UDP: ir.UDP{SourcePort: 53}},
				}},
			},
			want: true,
		},
		{
			name: "http",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"http"}}},
				ev: &v1.Event{Event: &ir.Flow{
					L4: ir.Layer4{TCP: ir.TCP{}},
					L7: ir.Layer7{HTTP: ir.HTTP{Method: "GET"}},
				}},
			},
			want: true,
		},
		{
			name: "icmp (v4)",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"icmp"}}},
				ev: &v1.Event{Event: &ir.Flow{
					L4: ir.Layer4{ICMPv4: ir.ICMP{Type: 1}},
				}},
			},
			want: true,
		},
		{
			name: "icmp (v6)",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"icmp"}}},
				ev: &v1.Event{Event: &ir.Flow{
					L4: ir.Layer4{ICMPv6: ir.ICMP{Type: 1}},
				}},
			},
			want: true,
		},
		{
			name: "vrrp",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"vrrp"}}},
				ev: &v1.Event{Event: &ir.Flow{
					L4: ir.Layer4{VRRP: ir.VRRP{Type: 1}},
				}},
			},
			want: true,
		},
		{
			name: "igmp",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"igmp"}}},
				ev: &v1.Event{Event: &ir.Flow{
					L4: ir.Layer4{IGMP: ir.IGMP{Type: 1}},
				}},
			},
			want: true,
		},
		{
			name: "multiple protocols",
			args: args{
				f: []*flowpb.FlowFilter{{Protocol: []string{"tcp", "kafka"}}},
				ev: &v1.Event{Event: &ir.Flow{
					L4: ir.Layer4{TCP: ir.TCP{SourcePort: 80}},
					L7: ir.Layer7{Kafka: ir.Kafka{Topic: "blee"}},
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
			fl, err := BuildFilterList(t.Context(), tt.args.f, []OnBuildFilter{&ProtocolFilter{}})
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
