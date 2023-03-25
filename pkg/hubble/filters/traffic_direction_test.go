// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestTrafficDirectionFilter(t *testing.T) {
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
			name: "nil",
			args: args{
				f: []*flowpb.FlowFilter{{
					TrafficDirection: []flowpb.TrafficDirection{
						flowpb.TrafficDirection_INGRESS,
					},
				}},
				ev: nil,
			},
			want: false,
		},
		{
			name: "match",
			args: args{
				f: []*flowpb.FlowFilter{{
					TrafficDirection: []flowpb.TrafficDirection{
						flowpb.TrafficDirection_INGRESS,
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					TrafficDirection: flowpb.TrafficDirection_INGRESS,
				}},
			},
			want: true,
		},
		{
			name: "no-match",
			args: args{
				f: []*flowpb.FlowFilter{{
					TrafficDirection: []flowpb.TrafficDirection{
						flowpb.TrafficDirection_INGRESS,
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					TrafficDirection: flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN,
				}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&TrafficDirectionFilter{}})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, fl.MatchOne(tt.args.ev))
		})
	}
}
