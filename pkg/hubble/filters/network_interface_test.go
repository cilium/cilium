// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestNetworkInterfaceFilter(t *testing.T) {
	type args struct {
		f  []*flowpb.FlowFilter
		ev *v1.Event
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "nil event",
			args: args{
				f: []*flowpb.FlowFilter{{
					Interface: []*flowpb.NetworkInterface{
						{
							Name: "eth1",
						},
					},
				}},
				ev: nil,
			},
			want: false,
		},
		{
			name: "empty filter (any interface) match",
			args: args{
				f: []*flowpb.FlowFilter{{
					Interface: []*flowpb.NetworkInterface{
						{},
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Interface: &flowpb.NetworkInterface{
						Index: 1,
						Name:  "eth1",
					},
				}},
			},
			want: true,
		},
		{
			name: "empty filter (any interface) miss",
			args: args{
				f: []*flowpb.FlowFilter{{
					Interface: []*flowpb.NetworkInterface{
						{},
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{}},
			},
			want: false,
		},
		{
			name: "wildcard",
			args: args{
				f: []*flowpb.FlowFilter{{
					Interface: []*flowpb.NetworkInterface{
						{},
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Interface: &flowpb.NetworkInterface{
						Index: 1,
						Name:  "eth1",
					},
				}},
			},
			want: true,
		},
		{
			name: "index match",
			args: args{
				f: []*flowpb.FlowFilter{{
					Interface: []*flowpb.NetworkInterface{
						{
							Index: 1,
						},
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Interface: &flowpb.NetworkInterface{
						Index: 1,
						Name:  "eth1",
					},
				}},
			},
			want: true,
		},
		{
			name: "name match",
			args: args{
				f: []*flowpb.FlowFilter{{
					Interface: []*flowpb.NetworkInterface{
						{
							Name: "eth1",
						},
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Interface: &flowpb.NetworkInterface{
						Index: 1,
						Name:  "eth1",
					},
				}},
			},
			want: true,
		},
		{
			name: "index and name match",
			args: args{
				f: []*flowpb.FlowFilter{{
					Interface: []*flowpb.NetworkInterface{
						{
							Index: 1,
							Name:  "eth1",
						},
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Interface: &flowpb.NetworkInterface{
						Index: 1,
						Name:  "eth1",
					},
				}},
			},
			want: true,
		},
		{
			name: "index mismatch",
			args: args{
				f: []*flowpb.FlowFilter{{
					Interface: []*flowpb.NetworkInterface{
						{
							Index: 42,
						},
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Interface: &flowpb.NetworkInterface{
						Index: 1,
						Name:  "eth1",
					},
				}},
			},
			want: false,
		},
		{
			name: "name mismatch",
			args: args{
				f: []*flowpb.FlowFilter{{
					Interface: []*flowpb.NetworkInterface{
						{
							Name: "cilium_vxlan",
						},
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Interface: &flowpb.NetworkInterface{
						Index: 1,
						Name:  "eth1",
					},
				}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(t.Context(), tt.args.f, []OnBuildFilter{&NetworkInterfaceFilter{}})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, fl.MatchOne(tt.args.ev))
		})
	}
}
