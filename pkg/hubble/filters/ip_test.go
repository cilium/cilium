// Copyright 2019-2020 Authors of Hubble
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
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "1.1.1.1", Destination: "2.2.2.2"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "2.2.2.2", Destination: "1.1.1.1"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "f00d::a10:0:0:9195", Destination: "ff02::1:ff00:b3e5"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "ff02::1:ff00:b3e5", Destination: "f00d::a10:0:0:9195"}}},
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
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "1.1.1.1", Destination: "2.2.2.2"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "2.2.2.2", Destination: "1.1.1.1"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "f00d::a10:0:0:9195", Destination: "ff02::1:ff00:b3e5"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "ff02::1:ff00:b3e5", Destination: "f00d::a10:0:0:9195"}}},
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
			name: "source and destination ip",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceIp:      []string{"1.1.1.1", "f00d::a10:0:0:9195"},
						DestinationIp: []string{"2.2.2.2", "ff02::1:ff00:b3e5"},
					},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "1.1.1.1", Destination: "2.2.2.2"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "2.2.2.2", Destination: "1.1.1.1"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "f00d::a10:0:0:9195", Destination: "ff02::1:ff00:b3e5"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "ff02::1:ff00:b3e5", Destination: "f00d::a10:0:0:9195"}}},
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
					{DestinationIp: []string{"2.2.2.2"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "1.1.1.1", Destination: "2.2.2.2"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "2.2.2.2", Destination: "1.1.1.1"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "1.1.1.1", Destination: "1.1.1.1"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "2.2.2.2", Destination: "2.2.2.2"}}},
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
					{Event: &flowpb.Flow{}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: ""}}},
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
			name: "source cidr",
			args: args{
				f: []*flowpb.FlowFilter{{SourceIp: []string{"1.1.1.0/24", "f00d::/16"}}},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "1.1.1.1", Destination: "2.2.2.2"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "2.2.2.2", Destination: "1.1.1.1"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "f00d::a10:0:0:9195", Destination: "ff02::1:ff00:b3e5"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Source: "ff02::1:ff00:b3e5", Destination: "f00d::a10:0:0:9195"}}},
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
					{Event: &flowpb.Flow{IP: &flowpb.IP{Destination: "1.1.1.1", Source: "2.2.2.2"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Destination: "2.2.2.2", Source: "1.1.1.1"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Destination: "f00d::a10:0:0:9195", Source: "ff02::1:ff00:b3e5"}}},
					{Event: &flowpb.Flow{IP: &flowpb.IP{Destination: "ff02::1:ff00:b3e5", Source: "f00d::a10:0:0:9195"}}},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&IPFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildFilterList(context.Background(), ) error = %v, wantErr %v", err, tt.wantErr)
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
