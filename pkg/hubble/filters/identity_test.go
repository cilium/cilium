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

func TestIdentityFilter(t *testing.T) {
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
			name: "source-nil",
			args: args{
				f: []*flowpb.FlowFilter{{
					SourceIdentity: []uint32{1},
				}},
				ev: nil,
			},
			want: false,
		},
		{
			name: "destination-nil",
			args: args{
				f: []*flowpb.FlowFilter{{
					DestinationIdentity: []uint32{1},
				}},
				ev: nil,
			},
			want: false,
		},
		{
			name: "source-positive",
			args: args{
				f: []*flowpb.FlowFilter{{
					SourceIdentity: []uint32{1, 2, 3},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Identity: 3},
				}},
			},
			want: true,
		},
		{
			name: "source-negative",
			args: args{
				f: []*flowpb.FlowFilter{{
					SourceIdentity: []uint32{1, 2, 3},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Identity: 4},
				}},
			},
			want: false,
		},
		{
			name: "destination-negative",
			args: args{
				f: []*flowpb.FlowFilter{{
					DestinationIdentity: []uint32{1, 2, 3},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Identity: 5},
				}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&IdentityFilter{}})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, fl.MatchOne(tt.args.ev))
		})
	}
}
