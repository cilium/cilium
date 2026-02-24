// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/ir"
)

func TestFlowTCPFilter(t *testing.T) {
	var argsfilter []*flowpb.FlowFilter
	var argsevent *v1.Event
	testflags := []struct {
		name   string
		argsf  []*flowpb.TCPFlags
		argsev ir.TCPFlags
		want   bool
	}{
		{
			name:   "filterSYNACK___eventSYNACK",
			argsf:  []*flowpb.TCPFlags{{SYN: true, ACK: true}},
			argsev: ir.TCPFlags{SYN: true, ACK: true},
			want:   true,
		},
		{
			name:   "filterSYNACK___eventSYN",
			argsf:  []*flowpb.TCPFlags{{SYN: true, ACK: true}},
			argsev: ir.TCPFlags{SYN: true},
			want:   false,
		},
		{
			name:   "filterSYN_OR_filterACK___eventSYN",
			argsf:  []*flowpb.TCPFlags{{SYN: true}, {ACK: true}},
			argsev: ir.TCPFlags{SYN: true},
			want:   true,
		},
		{
			name:   "filterSYN_OR_filterACK___eventSYNACK",
			argsf:  []*flowpb.TCPFlags{{SYN: true}, {ACK: true}},
			argsev: ir.TCPFlags{SYN: true, ACK: true},
			want:   true,
		},
		{
			name:   "filterSYN_OR_filterACK___eventPSHACK",
			argsf:  []*flowpb.TCPFlags{{SYN: true}, {ACK: true}},
			argsev: ir.TCPFlags{PSH: true, ACK: true},
			want:   true,
		},
		{
			name:   "filterSYN___eventSYN",
			argsf:  []*flowpb.TCPFlags{{SYN: true}},
			argsev: ir.TCPFlags{SYN: true},
			want:   true,
		},
		{
			name:   "filterSYN___eventSYNACK",
			argsf:  []*flowpb.TCPFlags{{SYN: true}},
			argsev: ir.TCPFlags{SYN: true, ACK: true},
			want:   true,
		},
		{
			name:   "filterFIN___eventRST",
			argsf:  []*flowpb.TCPFlags{{FIN: true}},
			argsev: ir.TCPFlags{RST: true},
			want:   false,
		},
		{
			name:   "filterSYN___eventPSH",
			argsf:  []*flowpb.TCPFlags{{SYN: true}},
			argsev: ir.TCPFlags{PSH: true},
			want:   false,
		},
		{
			name:   "filterURG___eventPSH",
			argsf:  []*flowpb.TCPFlags{{URG: true}},
			argsev: ir.TCPFlags{PSH: true},
			want:   false,
		},
		{
			name:   "filterRST___eventRST",
			argsf:  []*flowpb.TCPFlags{{RST: true}},
			argsev: ir.TCPFlags{RST: true},
			want:   true,
		},
		{
			name:   "filterFIN___eventFIN",
			argsf:  []*flowpb.TCPFlags{{FIN: true}},
			argsev: ir.TCPFlags{FIN: true},
			want:   true,
		},
		{
			name:   "filterPSH___eventPSHACK",
			argsf:  []*flowpb.TCPFlags{{PSH: true}},
			argsev: ir.TCPFlags{PSH: true, ACK: true},
			want:   true,
		},
		// regression test for GH-18830
		{
			name:   "TCP flow without flags",
			argsf:  []*flowpb.TCPFlags{{SYN: true}},
			argsev: ir.TCPFlags{},
			want:   false,
		},
	}

	for _, tt := range testflags {
		argsfilter = []*flowpb.FlowFilter{{TcpFlags: tt.argsf}}
		argsevent = &v1.Event{Event: &ir.Flow{L4: ir.Layer4{TCP: ir.TCP{Flags: tt.argsev}}}}

		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(t.Context(), argsfilter, []OnBuildFilter{&TCPFilter{}})
			if err != nil {
				t.Errorf("unexpected filter build error: %s", err)
			} else if got := fl.MatchOne(argsevent); got != tt.want {
				t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
