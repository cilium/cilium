// Copyright 2020 Authors of Hubble
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

func TestFlowTCPFilter(t *testing.T) {
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
			name: "filterSYN-ACK_eventSYN-ACK",
			args: args{
				f: []*flowpb.FlowFilter{{TcpFlags: []*flowpb.TCPFlags{
					{SYN: true, ACK: true}}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
						Flags: &flowpb.TCPFlags{SYN: true, ACK: true}}}},
				}},
			},
			want: true,
		},
		{
			name: "filterSYN_eventSYN",
			args: args{
				f: []*flowpb.FlowFilter{{TcpFlags: []*flowpb.TCPFlags{
					{SYN: true}}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
						Flags: &flowpb.TCPFlags{SYN: true}}}},
				}},
			},
			want: true,
		},
		{
			name: "filterSYN_eventSYN-ACK",
			args: args{
				f: []*flowpb.FlowFilter{{TcpFlags: []*flowpb.TCPFlags{
					{SYN: true}}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
						Flags: &flowpb.TCPFlags{SYN: true, ACK: true}}}},
				}},
			},
			want: true,
		},
		{
			name: "filterFIN_eventRST",
			args: args{
				f: []*flowpb.FlowFilter{{TcpFlags: []*flowpb.TCPFlags{
					{FIN: true}}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
						Flags: &flowpb.TCPFlags{RST: true}}}},
				}},
			},
			want: false,
		},
		{
			name: "filterSYN_eventPSH",
			args: args{
				f: []*flowpb.FlowFilter{{TcpFlags: []*flowpb.TCPFlags{
					{SYN: true}}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
						Flags: &flowpb.TCPFlags{PSH: true}}}},
				}},
			},
			want: false,
		},
		{
			name: "filterURG_eventPSH",
			args: args{
				f: []*flowpb.FlowFilter{{TcpFlags: []*flowpb.TCPFlags{
					{URG: true}}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
						Flags: &flowpb.TCPFlags{PSH: true}}}},
				}},
			},
			want: false,
		},
		{
			name: "filterRST_eventRST",
			args: args{
				f: []*flowpb.FlowFilter{{TcpFlags: []*flowpb.TCPFlags{
					{RST: true}}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
						Flags: &flowpb.TCPFlags{RST: true}}}},
				}},
			},
			want: true,
		},
		{
			name: "filterFIN_eventFIN",
			args: args{
				f: []*flowpb.FlowFilter{{TcpFlags: []*flowpb.TCPFlags{
					{FIN: true}}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
						Flags: &flowpb.TCPFlags{FIN: true}}}},
				}},
			},
			want: true,
		},
		{
			name: "filterPSH_eventPSHACK",
			args: args{
				f: []*flowpb.FlowFilter{{TcpFlags: []*flowpb.TCPFlags{
					{PSH: true}}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
						Flags: &flowpb.TCPFlags{PSH: true, ACK: true}}}},
				}},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&TCPFilter{}})
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
