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
	var argsfilter []*flowpb.FlowFilter
	var argsevent *v1.Event
	testflags := []struct {
		name   string
		argsf  []*flowpb.TCPFlags
		argsev *flowpb.TCPFlags
		want   bool
	}{
		{
			name:   "filterSYNACK___eventSYNACK",
			argsf:  []*flowpb.TCPFlags{{SYN: true, ACK: true}},
			argsev: &flowpb.TCPFlags{SYN: true, ACK: true},
			want:   true,
		},
		{
			name:   "filterSYNACK___eventSYN",
			argsf:  []*flowpb.TCPFlags{{SYN: true, ACK: true}},
			argsev: &flowpb.TCPFlags{SYN: true},
			want:   false,
		},
		{
			name:   "filterSYN_OR_filterACK___eventSYN",
			argsf:  []*flowpb.TCPFlags{{SYN: true}, {ACK: true}},
			argsev: &flowpb.TCPFlags{SYN: true},
			want:   true,
		},
		{
			name:   "filterSYN_OR_filterACK___eventSYNACK",
			argsf:  []*flowpb.TCPFlags{{SYN: true}, {ACK: true}},
			argsev: &flowpb.TCPFlags{SYN: true, ACK: true},
			want:   true,
		},
		{
			name:   "filterSYN_OR_filterACK___eventPSHACK",
			argsf:  []*flowpb.TCPFlags{{SYN: true}, {ACK: true}},
			argsev: &flowpb.TCPFlags{PSH: true, ACK: true},
			want:   true,
		},
		{
			name:   "filterSYN___eventSYN",
			argsf:  []*flowpb.TCPFlags{{SYN: true}},
			argsev: &flowpb.TCPFlags{SYN: true},
			want:   true,
		},
		{
			name:   "filterSYN___eventSYNACK",
			argsf:  []*flowpb.TCPFlags{{SYN: true}},
			argsev: &flowpb.TCPFlags{SYN: true, ACK: true},
			want:   true,
		},
		{
			name:   "filterFIN___eventRST",
			argsf:  []*flowpb.TCPFlags{{FIN: true}},
			argsev: &flowpb.TCPFlags{RST: true},
			want:   false,
		},
		{
			name:   "filterSYN___eventPSH",
			argsf:  []*flowpb.TCPFlags{{SYN: true}},
			argsev: &flowpb.TCPFlags{PSH: true},
			want:   false,
		},
		{
			name:   "filterURG___eventPSH",
			argsf:  []*flowpb.TCPFlags{{URG: true}},
			argsev: &flowpb.TCPFlags{PSH: true},
			want:   false,
		},
		{
			name:   "filterRST___eventRST",
			argsf:  []*flowpb.TCPFlags{{RST: true}},
			argsev: &flowpb.TCPFlags{RST: true},
			want:   true,
		},
		{
			name:   "filterFIN___eventFIN",
			argsf:  []*flowpb.TCPFlags{{FIN: true}},
			argsev: &flowpb.TCPFlags{FIN: true},
			want:   true,
		},
		{
			name:   "filterPSH___eventPSHACK",
			argsf:  []*flowpb.TCPFlags{{PSH: true}},
			argsev: &flowpb.TCPFlags{PSH: true, ACK: true},
			want:   true,
		},
	}

	for _, tt := range testflags {
		argsfilter = []*flowpb.FlowFilter{{TcpFlags: tt.argsf}}
		argsevent = &v1.Event{Event: &flowpb.Flow{
			L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{Flags: tt.argsev}}}}}
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), argsfilter, []OnBuildFilter{&TCPFilter{}})
			if err != nil {
				return
			}
			if got := fl.MatchOne(argsevent); got != tt.want {
				t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
