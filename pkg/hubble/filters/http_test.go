// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"strings"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/monitor/api"
)

func TestHTTPFilters(t *testing.T) {
	httpFlow := func(http *flowpb.HTTP) *v1.Event {
		return &v1.Event{
			Event: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					Type: api.MessageTypeAccessLog,
				},
				L7: &flowpb.Layer7{
					Record: &flowpb.Layer7_Http{
						Http: http,
					},
				}},
		}
	}

	type args struct {
		f  []*flowpb.FlowFilter
		ev []*v1.Event
	}

	tests := []struct {
		name            string
		args            args
		wantErr         bool
		wantErrContains string
		want            []bool
	}{
		// status code filters
		{
			name: "status code full",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpStatusCode: []string{"200", "302"},
						EventType:      []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
				ev: []*v1.Event{
					httpFlow(&flowpb.HTTP{Code: 200}),
					httpFlow(&flowpb.HTTP{Code: 302}),
					httpFlow(&flowpb.HTTP{Code: 404}),
					httpFlow(&flowpb.HTTP{Code: 500}),
				},
			},
			want: []bool{
				true,
				true,
				false,
				false,
			},
			wantErr: false,
		},
		{
			name: "status code prefix",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpStatusCode: []string{"40+", "5+"},
						EventType:      []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
				ev: []*v1.Event{
					httpFlow(&flowpb.HTTP{Code: 302}),
					httpFlow(&flowpb.HTTP{Code: 400}),
					httpFlow(&flowpb.HTTP{Code: 404}),
					httpFlow(&flowpb.HTTP{Code: 410}),
					httpFlow(&flowpb.HTTP{Code: 004}),
					httpFlow(&flowpb.HTTP{Code: 500}),
					httpFlow(&flowpb.HTTP{Code: 501}),
					httpFlow(&flowpb.HTTP{Code: 510}),
					httpFlow(&flowpb.HTTP{Code: 050}),
				},
			},
			want: []bool{
				false,
				true,
				true,
				false,
				false,
				true,
				true,
				true,
				false,
			},
			wantErr: false,
		},
		{
			name: "invalid data",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpStatusCode: []string{"200"},
						EventType:      []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{}},
					httpFlow(&flowpb.HTTP{}),
					httpFlow(&flowpb.HTTP{Code: 777}),
				},
			},
			want: []bool{
				false,
				false,
				false,
			},
			wantErr: false,
		},
		{
			name: "invalid empty filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpStatusCode: []string{""},
						EventType:      []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid catch-all prefix",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpStatusCode: []string{"+"},
						EventType:      []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid status code",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpStatusCode: []string{"909"},
						EventType:      []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid status code text",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpStatusCode: []string{"HTTP 200 OK"},
						EventType:      []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid status code prefix",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpStatusCode: []string{"3++"},
						EventType:      []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid status code prefix",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpStatusCode: []string{"3+0"},
						EventType:      []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "empty event type filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpStatusCode: []string{"200"},
						EventType:      []*flowpb.EventTypeFilter{},
					},
				},
				ev: []*v1.Event{
					httpFlow(&flowpb.HTTP{Code: 200}),
				},
			},
			want: []bool{
				true,
			},
			wantErr: false,
		},
		{
			name: "compatible event type filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpStatusCode: []string{"200"},
						EventType: []*flowpb.EventTypeFilter{
							{Type: api.MessageTypeAccessLog},
							{Type: api.MessageTypeTrace},
						},
					},
				},
				ev: []*v1.Event{
					httpFlow(&flowpb.HTTP{Code: 200}),
				},
			},
			want: []bool{
				true,
			},
			wantErr: false,
		},
		// method filters
		{
			name: "basic http method filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpMethod: []string{"GET"},
						EventType: []*flowpb.EventTypeFilter{
							{Type: api.MessageTypeAccessLog},
							{Type: api.MessageTypeTrace},
						},
					},
					{
						HttpMethod: []string{"POST"},
						EventType: []*flowpb.EventTypeFilter{
							{Type: api.MessageTypeAccessLog},
							{Type: api.MessageTypeTrace},
						},
					},
				},
				ev: []*v1.Event{
					httpFlow(&flowpb.HTTP{Method: "gEt"}),
				},
			},
			want: []bool{
				true,
				false,
			},
			wantErr: false,
		},
		{
			name: "http method wrong type",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpMethod: []string{"GET"},
						EventType: []*flowpb.EventTypeFilter{
							{Type: api.MessageTypeTrace},
						},
					},
				},
				ev: []*v1.Event{
					httpFlow(&flowpb.HTTP{Method: "gEt"}),
				},
			},
			wantErr:         true,
			wantErrContains: "http method requires the event type filter",
		},
		{
			name: "http method wrong type",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpMethod: []string{"PUT"},
						EventType: []*flowpb.EventTypeFilter{
							{Type: api.MessageTypeAccessLog},
							{Type: api.MessageTypeTrace},
						},
					},
					{
						HttpMethod: []string{"POST"},
						EventType: []*flowpb.EventTypeFilter{
							{Type: api.MessageTypeAccessLog},
							{Type: api.MessageTypeTrace},
						},
					},
				},
				ev: []*v1.Event{
					httpFlow(&flowpb.HTTP{Method: "DELETE"}),
				},
			},
			want: []bool{
				false,
				false,
			},
		},
		// path filters
		{
			name: "path full",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpPath:  []string{"/docs/[a-z]+", "/post/\\d+"},
						EventType: []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
				ev: []*v1.Event{
					httpFlow(&flowpb.HTTP{Url: "/docs/"}),
					httpFlow(&flowpb.HTTP{Url: "/docs/tutorial/"}),
					httpFlow(&flowpb.HTTP{Url: "/post/"}),
					httpFlow(&flowpb.HTTP{Url: "/post/0"}),
					httpFlow(&flowpb.HTTP{Url: "/post/slug"}),
					httpFlow(&flowpb.HTTP{Url: "/post/123?key=value"}),
					httpFlow(&flowpb.HTTP{Url: "/slug"}),
				},
			},
			want: []bool{
				false,
				true,
				false,
				true,
				false,
				true,
				false,
			},
			wantErr: false,
		},
		{
			name: "invalid uri",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpPath:  []string{"/post/\\d+"},
						EventType: []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
				ev: []*v1.Event{
					httpFlow(&flowpb.HTTP{Url: "/post/0"}),
					httpFlow(&flowpb.HTTP{Url: "?/post/0"}),
				},
			},
			want: []bool{
				true,
				false,
			},
			wantErr: false,
		},
		{
			name: "invalid path filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HttpPath:  []string{"("},
						EventType: []*flowpb.EventTypeFilter{{Type: api.MessageTypeAccessLog}},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&HTTPFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf(`"%s" error = %v, wantErr %v`, tt.name, err, tt.wantErr)
				return
			}
			if err != nil {
				if tt.wantErrContains != "" {
					if !strings.Contains(err.Error(), tt.wantErrContains) {
						t.Errorf(
							`"%s" error does not contain "%s"`,
							err.Error(), tt.wantErrContains,
						)
					}
				}
				return
			}
			for i, ev := range tt.args.ev {
				if got := fl.MatchOne(ev); got != tt.want[i] {
					t.Errorf("\"%s\" got %d = %v, want %v", tt.name, i, got, tt.want[i])
				}
			}
		})
	}
}
