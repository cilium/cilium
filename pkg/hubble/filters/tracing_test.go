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

func TestTraceIDFilter(t *testing.T) {
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
			name: "match example trace ID",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						TraceId: []string{"4bf92f3577b34da6a3ce929d0e0e4736"},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					TraceContext: &flowpb.TraceContext{
						Parent: &flowpb.TraceParent{
							TraceId: "4bf92f3577b34da6a3ce929d0e0e4736",
						},
					},
				}},
			},
			want: true,
		}, {
			name: "match example trace ID with multiple input filters",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						TraceId: []string{
							"deadbeefcafe",
							"4bf92f3577b34da6a3ce929d0e0e4736",
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					TraceContext: &flowpb.TraceContext{
						Parent: &flowpb.TraceParent{
							TraceId: "4bf92f3577b34da6a3ce929d0e0e4736",
						},
					},
				}},
			},
			want: true,
		}, {
			name: "empty trace ID filter on flow without trace ID",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						TraceId: []string{""},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{}},
			},
			want: true,
		}, {
			name: "empty trace ID filter on flow with trace ID",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						TraceId: []string{""},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					TraceContext: &flowpb.TraceContext{
						Parent: &flowpb.TraceParent{
							TraceId: "4bf92f3577b34da6a3ce929d0e0e4736",
						},
					},
				}},
			},
			want: false,
		}, {
			name: "don't match example trace ID",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						TraceId: []string{"deadbeefcafe"},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					TraceContext: &flowpb.TraceContext{
						Parent: &flowpb.TraceParent{
							TraceId: "4bf92f3577b34da6a3ce929d0e0e4736",
						},
					},
				}},
			},
			want: false,
		}, {
			name: "no trace ID in flow",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						TraceId: []string{"4bf92f3577b34da6a3ce929d0e0e4736"},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{}},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&TraceIDFilter{}})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, fl.MatchOne(tt.args.ev))
		})
	}
}
