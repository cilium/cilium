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

func TestUUIDFilter(t *testing.T) {
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
					Uuid: []string{"43eea867-dd4b-4e5e-b2b8-fe80e0f51b06"},
				}},
				ev: nil,
			},
			want: false,
		},
		{
			name: "match",
			args: args{
				f: []*flowpb.FlowFilter{{
					Uuid: []string{
						"43eea867-dd4b-4e5e-b2b8-fe80e0f51b06",
						"4eb4d680-4793-43af-8446-79d72254084c",
						"7ac83829-a655-4a9b-9729-70f8683858a5",
						"a82c2c32-f410-47fb-9343-7788ea734c79", // this one
						"e3549e80-6216-4179-93ed-b00d33b939ff",
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Uuid: "a82c2c32-f410-47fb-9343-7788ea734c79",
				}},
			},
			want: true,
		},
		{
			name: "no-match",
			args: args{
				f: []*flowpb.FlowFilter{{
					Uuid: []string{
						"43eea867-dd4b-4e5e-b2b8-fe80e0f51b06",
						"4eb4d680-4793-43af-8446-79d72254084c",
						"7ac83829-a655-4a9b-9729-70f8683858a5",
						"e3549e80-6216-4179-93ed-b00d33b939ff",
					},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					Uuid: "a82c2c32-f410-47fb-9343-7788ea734c79",
				}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&UUIDFilter{}})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, fl.MatchOne(tt.args.ev))
		})
	}
}
