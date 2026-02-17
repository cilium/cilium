// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"net"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/ir"
)

func TestIPFilter(t *testing.T) {
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
			name: "source ip",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourceIp: []string{"1.1.1.1", "f00d::a10:0:0:9195"}},
				},
				ev: []*v1.Event{
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("10.0.0.2"), Destination: net.ParseIP("1.1.1.1")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("f00d::a10:0:0:9195"), Destination: net.ParseIP("ff02::1:ff00:b3e5")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("ff02::1:ff00:b3e5"), Destination: net.ParseIP("f00d::a10:0:0:9195")}}},
				},
			},
			want: []bool{
				true,
				false,
				true,
				false,
			},
		},
		{
			name: "destination ip",
			args: args{
				f: []*flowpb.FlowFilter{
					{DestinationIp: []string{"1.1.1.1", "f00d::a10:0:0:9195"}},
				},
				ev: []*v1.Event{
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("10.0.0.2"), Destination: net.ParseIP("1.1.1.1")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("f00d::a10:0:0:9195"), Destination: net.ParseIP("ff02::1:ff00:b3e5")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("ff02::1:ff00:b3e5"), Destination: net.ParseIP("f00d::a10:0:0:9195")}}},
				},
			},
			want: []bool{
				false,
				true,
				false,
				true,
			},
		},
		{
			name: "snat ip",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourceIpXlated: []string{"2.2.2.2", "9bf2:8d06:6d34:da3b::33c5"}},
				},
				ev: []*v1.Event{
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("2.2.2.2"), Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), SourceXlated: "2.2.2.3", Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), SourceXlated: "2.2.2.2", Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("f00d::a10:0:0:9195"), Destination: net.ParseIP("ff02::1:ff00:b3e5")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("f00d::a10:0:0:9195"), Destination: net.ParseIP("9bf2:8d06:6d34:da3b::33c5")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("f00d::a10:0:0:9195"), SourceXlated: "9bf2:8d06:6d34:da3b::33c5", Destination: net.ParseIP("ff02::1:ff00:b3e5")}}},
				},
			},
			want: []bool{
				false,
				false,
				false,
				true,
				false,
				false,
				true,
			},
		},
		{
			name: "source and destination ip",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceIp:      []string{"1.1.1.1", "f00d::a10:0:0:9195"},
						DestinationIp: []string{"10.0.0.2", "ff02::1:ff00:b3e5"},
					},
				},
				ev: []*v1.Event{
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("10.0.0.2"), Destination: net.ParseIP("1.1.1.1")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("f00d::a10:0:0:9195"), Destination: net.ParseIP("ff02::1:ff00:b3e5")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("ff02::1:ff00:b3e5"), Destination: net.ParseIP("f00d::a10:0:0:9195")}}},
				},
			},
			want: []bool{
				true,
				false,
				true,
				false,
			},
		},
		{
			name: "source and snat and destination ip",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceIp:       []string{"1.1.1.1", "f00d::a10:0:0:9195"},
						SourceIpXlated: []string{"2.2.2.2", "9bf2:8d06:6d34:da3b::33c5"},
						DestinationIp:  []string{"10.0.0.2", "ff02::1:ff00:b3e5"},
					},
				},
				ev: []*v1.Event{
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), SourceXlated: "2.2.2.2", Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("f00d::a10:0:0:9195"), SourceXlated: "9bf2:8d06:6d34:da3b::33c5", Destination: net.ParseIP("ff02::1:ff00:b3e5")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("f00d::a10:0:0:9195"), SourceXlated: "ff02::1:ff00:b3e5", Destination: net.ParseIP("9bf2:8d06:6d34:da3b::33c5")}}},
				},
			},
			want: []bool{
				true,
				false,
				true,
				false,
			},
		},
		{
			name: "source or destination ip",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourceIp: []string{"1.1.1.1"}},
					{DestinationIp: []string{"10.0.0.2"}},
				},
				ev: []*v1.Event{
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("10.0.0.2"), Destination: net.ParseIP("1.1.1.1")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), Destination: net.ParseIP("1.1.1.1")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("10.0.0.2"), Destination: net.ParseIP("10.0.0.2")}}},
				},
			},
			want: []bool{
				true,
				false,
				true,
				true,
			},
		},
		{
			name: "invalid data",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourceIp: []string{"1.1.1.1"}},
				},
				ev: []*v1.Event{
					nil,
					{},
					{Event: &ir.Flow{}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("")}}},
				},
			},
			want: []bool{
				false,
				false,
				false,
				false,
			},
		},
		{
			name: "invalid source ip filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourceIp: []string{"320.320.320.320"}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid destination ip filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{DestinationIp: []string{""}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid snat ip filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourceIpXlated: []string{""}},
				},
			},
			wantErr: true,
		},
		{
			name: "source cidr",
			args: args{
				f: []*flowpb.FlowFilter{{SourceIp: []string{"1.1.1.0/24", "f00d::/16"}}},
				ev: []*v1.Event{
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("10.0.0.2"), Destination: net.ParseIP("1.1.1.1")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("f00d::a10:0:0:9195"), Destination: net.ParseIP("ff02::1:ff00:b3e5")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("ff02::1:ff00:b3e5"), Destination: net.ParseIP("f00d::a10:0:0:9195")}}},
				},
			},
			want: []bool{
				true,
				false,
				true,
				false,
			},
		},
		{
			name: "destination cidr",
			args: args{
				f: []*flowpb.FlowFilter{{DestinationIp: []string{"1.1.1.0/24", "f00d::/16"}}},
				ev: []*v1.Event{
					{Event: &ir.Flow{IP: ir.IP{Destination: net.ParseIP("1.1.1.1"), Source: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Destination: net.ParseIP("10.0.0.2"), Source: net.ParseIP("1.1.1.1")}}},
					{Event: &ir.Flow{IP: ir.IP{Destination: net.ParseIP("f00d::a10:0:0:9195"), Source: net.ParseIP("ff02::1:ff00:b3e5")}}},
					{Event: &ir.Flow{IP: ir.IP{Destination: net.ParseIP("ff02::1:ff00:b3e5"), Source: net.ParseIP("f00d::a10:0:0:9195")}}},
				},
			},
			want: []bool{
				true,
				false,
				true,
				false,
			},
		},
		{
			name: "snat cidr",
			args: args{
				f: []*flowpb.FlowFilter{{SourceIpXlated: []string{"1.1.1.0/24", "9bf2::/16"}}},
				ev: []*v1.Event{
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), Destination: net.ParseIP("1.1.1.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), SourceXlated: "1.1.2.1", Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("1.1.1.1"), SourceXlated: "1.1.1.2", Destination: net.ParseIP("10.0.0.2")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("f00d::a10:0:0:9195"), Destination: net.ParseIP("ff02::1:ff00:b3e5")}}},
					{Event: &ir.Flow{IP: ir.IP{Source: net.ParseIP("ff02::1:ff00:b3e5"), SourceXlated: "9bf2:8d06:6d34:da3b::33c5", Destination: net.ParseIP("f00d::a10:0:0:9195")}}},
				},
			},
			want: []bool{
				false,
				false,
				true,
				false,
				true,
			},
		},
		{
			name: "invalid source cidr filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourceIp: []string{"1.1.1.1/1234"}},
					{SourceIp: []string{"2001::/1234"}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid destination cidr filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{DestinationIp: []string{"1.1.1.1/1234"}},
					{DestinationIp: []string{"2001::/1234"}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid snat cidr filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourceIpXlated: []string{"1.1.1.1/1234"}},
					{SourceIpXlated: []string{"2001::/1234"}},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(t.Context(), tt.args.f, []OnBuildFilter{&IPFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildFilterList(t.Context(), ) error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i, ev := range tt.args.ev {
				if filterResult := fl.MatchOne(ev); filterResult != tt.want[i] {
					t.Errorf("\"%s\" filterResult %d = %v, want %v", tt.name, i, filterResult, tt.want[i])
				}
			}
		})
	}
}

func TestIPVersionFilter(t *testing.T) {
	allvers := []*v1.Event{
		{Event: &ir.Flow{IP: ir.IP{IPVersion: flowpb.IPVersion_IPv4}}},
		{Event: &ir.Flow{IP: ir.IP{IPVersion: flowpb.IPVersion_IPv6}}},
		{Event: &ir.Flow{IP: ir.IP{IPVersion: flowpb.IPVersion_IP_NOT_USED}}},
	}
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
			name: "ipv4 test",
			args: args{
				f: []*flowpb.FlowFilter{
					{IpVersion: []flowpb.IPVersion{flowpb.IPVersion_IPv4}},
				},
				ev: allvers,
			},
			want: []bool{
				true,
				false,
				false,
			},
		},
		{
			name: "ipv6 test",
			args: args{
				f: []*flowpb.FlowFilter{
					{IpVersion: []flowpb.IPVersion{flowpb.IPVersion_IPv6}},
				},
				ev: allvers,
			},
			want: []bool{
				false,
				true,
				false,
			},
		},
		{
			name: "unknown network protocol test",
			args: args{
				f: []*flowpb.FlowFilter{
					{IpVersion: []flowpb.IPVersion{flowpb.IPVersion_IP_NOT_USED}},
				},
				ev: allvers,
			},
			want: []bool{
				false,
				false,
				true,
			},
		},
		{
			name: "both ipv4 and ipv6 allow test",
			args: args{
				f: []*flowpb.FlowFilter{
					{IpVersion: []flowpb.IPVersion{flowpb.IPVersion_IPv4}},
					{IpVersion: []flowpb.IPVersion{flowpb.IPVersion_IPv6}},
				},
				ev: allvers,
			},
			want: []bool{
				true,
				true,
				false,
			},
		},
		{
			name: "all ipv4,ipv6,unknown allow test",
			args: args{
				f: []*flowpb.FlowFilter{
					{IpVersion: []flowpb.IPVersion{flowpb.IPVersion_IPv4}},
					{IpVersion: []flowpb.IPVersion{flowpb.IPVersion_IPv6}},
					{IpVersion: []flowpb.IPVersion{flowpb.IPVersion_IP_NOT_USED}},
				},
				ev: allvers,
			},
			want: []bool{
				true,
				true,
				true,
			},
		},
		{
			name: "test with non-flow event",
			args: args{
				f: []*flowpb.FlowFilter{
					{IpVersion: []flowpb.IPVersion{flowpb.IPVersion_IPv4}},
					{IpVersion: []flowpb.IPVersion{flowpb.IPVersion_IPv6}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.AgentEvent{}},
				},
			},
			want: []bool{
				false,
			},
		},
		{
			name: "test with non-flow event and IP_NOT_USED",
			args: args{
				f: []*flowpb.FlowFilter{
					{IpVersion: []flowpb.IPVersion{flowpb.IPVersion_IP_NOT_USED}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.AgentEvent{}},
				},
			},
			want: []bool{
				false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(t.Context(), tt.args.f, []OnBuildFilter{&IPVersionFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildFilterList(t.Context(), ) error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i, ev := range tt.args.ev {
				if filterResult := fl.MatchOne(ev); filterResult != tt.want[i] {
					t.Errorf("\"%s\" filterResult %d = %v, want %v", tt.name, i, filterResult, tt.want[i])
				}
			}
		})
	}
}
