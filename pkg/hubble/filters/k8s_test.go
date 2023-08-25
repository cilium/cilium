// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestPodFilter(t *testing.T) {
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
			name: "source pod",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourcePod: []string{"xwing", "default/tiefighter"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "default", PodName: "xwing"}}},
					{Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "default", PodName: "tiefighter"}}},
					{Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "kube-system", PodName: "xwing"}}},
					{Event: &flowpb.Flow{Destination: &flowpb.Endpoint{Namespace: "default", PodName: "xwing"}}},
				},
			},
			want: []bool{
				true,
				true,
				false,
				false,
			},
		},
		{
			name: "destination pod",
			args: args{
				f: []*flowpb.FlowFilter{
					{DestinationPod: []string{"xwing", "default/tiefighter"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{Destination: &flowpb.Endpoint{Namespace: "default", PodName: "xwing"}}},
					{Event: &flowpb.Flow{Destination: &flowpb.Endpoint{Namespace: "default", PodName: "tiefighter"}}},
					{Event: &flowpb.Flow{Destination: &flowpb.Endpoint{Namespace: "kube-system", PodName: "xwing"}}},
					{Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "default", PodName: "xwing"}}},
				},
			},
			want: []bool{
				true,
				true,
				false,
				false,
			},
		},
		{
			name: "source and destination pod",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourcePod:      []string{"xwing", "tiefighter"},
						DestinationPod: []string{"deathstar"},
					},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "default", PodName: "xwing"},
						Destination: &flowpb.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &flowpb.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "default", PodName: "deathstar"},
						Destination: &flowpb.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &flowpb.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
				},
			},
			want: []bool{
				true,
				true,
				false,
				false,
			},
		},
		{
			name: "source or destination pod",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourcePod: []string{"xwing"}},
					{DestinationPod: []string{"deathstar"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "default", PodName: "xwing"},
						Destination: &flowpb.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &flowpb.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "default", PodName: "deathstar"},
						Destination: &flowpb.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &flowpb.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
				},
			},
			want: []bool{
				true,
				true,
				false,
				false,
			},
		},
		{
			name: "namespace filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourcePod: []string{"kube-system/"}},
					{DestinationPod: []string{"kube-system/"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "kube-system", PodName: "coredns"},
						Destination: &flowpb.Endpoint{Namespace: "kube-system", PodName: "kube-proxy"},
					}},
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &flowpb.Endpoint{Namespace: "kube-system", PodName: "coredns"},
					}},
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "kube-system", PodName: "coredns"},
						Destination: &flowpb.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &flowpb.Flow{
						Source:      &flowpb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &flowpb.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
				},
			},
			want: []bool{
				true,
				true,
				true,
				false,
			},
		},
		{
			name: "prefix filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourcePod: []string{"xwing", "kube-system/coredns-"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{
						Source: &flowpb.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &flowpb.Flow{
						Source: &flowpb.Endpoint{Namespace: "default", PodName: "xwing-t-65b"},
					}},
					{Event: &flowpb.Flow{
						Source: &flowpb.Endpoint{Namespace: "kube-system", PodName: "coredns-12345"},
					}},
					{Event: &flowpb.Flow{
						Source: &flowpb.Endpoint{Namespace: "kube-system", PodName: "-coredns-12345"},
					}},
					{Event: &flowpb.Flow{
						Source: &flowpb.Endpoint{Namespace: "default", PodName: "tiefighter"},
					}},
				},
			},
			want: []bool{
				true,
				true,
				true,
				false,
				false,
			},
		},
		{
			name: "invalid data",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourcePod: []string{"xwing"}},
				},
				ev: []*v1.Event{
					nil,
					{},
					{Event: &flowpb.Flow{}},
					{Event: &flowpb.Flow{Source: &flowpb.Endpoint{Namespace: "", PodName: "xwing"}}},
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
			name: "invalid source pod filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourcePod: []string{""}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid destination pod filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{DestinationPod: []string{""}},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&PodFilter{}})
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

func TestServiceFilter(t *testing.T) {
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
			name: "source service",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourceService: []string{"deathstar", "kube-system/kube-dns"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{SourceService: &flowpb.Service{Namespace: "default", Name: "xwing"}}},
					{Event: &flowpb.Flow{SourceService: &flowpb.Service{Namespace: "default", Name: "deathstar"}}},
					{Event: &flowpb.Flow{SourceService: &flowpb.Service{Namespace: "kube-system", Name: "kube-dns"}}},
					{Event: &flowpb.Flow{DestinationService: &flowpb.Service{Namespace: "kube-system", Name: "deathstar"}}},
				},
			},
			want: []bool{
				false,
				true,
				true,
				false,
			},
		},
		{
			name: "destination service",
			args: args{
				f: []*flowpb.FlowFilter{
					{DestinationService: []string{"default/", "kube-system/kube-"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{DestinationService: &flowpb.Service{Namespace: "default", Name: "xwing"}}},
					{Event: &flowpb.Flow{DestinationService: &flowpb.Service{Namespace: "default", Name: "deathstar"}}},
					{Event: &flowpb.Flow{DestinationService: &flowpb.Service{Namespace: "kube-system", Name: "kube-dns"}}},
					{Event: &flowpb.Flow{SourceService: &flowpb.Service{Namespace: "kube-system", Name: "deathstar"}}},
				},
			},
			want: []bool{
				true,
				true,
				true,
				false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&ServiceFilter{}})
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
