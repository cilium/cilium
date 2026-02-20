// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/ir"
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
					{Event: &ir.Flow{Source: ir.Endpoint{Namespace: "default", PodName: "xwing"}}},
					{Event: &ir.Flow{Source: ir.Endpoint{Namespace: "default", PodName: "tiefighter"}}},
					{Event: &ir.Flow{Source: ir.Endpoint{Namespace: "kube-system", PodName: "xwing"}}},
					{Event: &ir.Flow{Destination: ir.Endpoint{Namespace: "default", PodName: "xwing"}}},
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
					{Event: &ir.Flow{Destination: ir.Endpoint{Namespace: "default", PodName: "xwing"}}},
					{Event: &ir.Flow{Destination: ir.Endpoint{Namespace: "default", PodName: "tiefighter"}}},
					{Event: &ir.Flow{Destination: ir.Endpoint{Namespace: "kube-system", PodName: "xwing"}}},
					{Event: &ir.Flow{Source: ir.Endpoint{Namespace: "default", PodName: "xwing"}}},
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
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "xwing"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "deathstar"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "xwing"},
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
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "xwing"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "deathstar"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "xwing"},
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
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "kube-system", PodName: "coredns"},
						Destination: ir.Endpoint{Namespace: "kube-system", PodName: "kube-proxy"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: ir.Endpoint{Namespace: "kube-system", PodName: "coredns"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "kube-system", PodName: "coredns"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "xwing"},
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
					{Event: &ir.Flow{
						Source: ir.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &ir.Flow{
						Source: ir.Endpoint{Namespace: "default", PodName: "xwing-t-65b"},
					}},
					{Event: &ir.Flow{
						Source: ir.Endpoint{Namespace: "kube-system", PodName: "coredns-12345"},
					}},
					{Event: &ir.Flow{
						Source: ir.Endpoint{Namespace: "kube-system", PodName: "-coredns-12345"},
					}},
					{Event: &ir.Flow{
						Source: ir.Endpoint{Namespace: "default", PodName: "tiefighter"},
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
					{Event: &ir.Flow{}},
					{Event: &ir.Flow{Source: ir.Endpoint{Namespace: "", PodName: "xwing"}}},
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
		{
			name: "all namespaces",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourcePod: []string{"/xwing"}},
					{DestinationPod: []string{"/xwing"}},
				},
				ev: []*v1.Event{
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "kube-system", PodName: "coredns"},
						Destination: ir.Endpoint{Namespace: "kube-system", PodName: "kube-proxy"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: ir.Endpoint{Namespace: "kube-system", PodName: "coredns"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "kube-system", PodName: "coredns"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "hoth", PodName: "tiefighter"},
						Destination: ir.Endpoint{Namespace: "endor", PodName: "xwing"},
					}},
					{Event: &ir.Flow{
						Source:      ir.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: ir.Endpoint{Namespace: "default", PodName: "ywing"},
					}},
				},
			},
			want: []bool{
				false,
				false,
				true,
				true,
				true,
				false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(t.Context(), tt.args.f, []OnBuildFilter{&PodFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildFilterList(t.Context(), ) error = %v, wantErr %v", err, tt.wantErr)
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
					{Event: &ir.Flow{SourceService: ir.Service{Namespace: "default", Name: "xwing"}}},
					{Event: &ir.Flow{SourceService: ir.Service{Namespace: "default", Name: "deathstar"}}},
					{Event: &ir.Flow{SourceService: ir.Service{Namespace: "kube-system", Name: "kube-dns"}}},
					{Event: &ir.Flow{DestinationService: ir.Service{Namespace: "kube-system", Name: "deathstar"}}},
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
					{Event: &ir.Flow{DestinationService: ir.Service{Namespace: "default", Name: "xwing"}}},
					{Event: &ir.Flow{DestinationService: ir.Service{Namespace: "default", Name: "deathstar"}}},
					{Event: &ir.Flow{DestinationService: ir.Service{Namespace: "kube-system", Name: "kube-dns"}}},
					{Event: &ir.Flow{SourceService: ir.Service{Namespace: "kube-system", Name: "deathstar"}}},
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
			name: "any namespace",
			args: args{
				f: []*flowpb.FlowFilter{
					{DestinationService: []string{"/kube-"}},
				},
				ev: []*v1.Event{
					{Event: &ir.Flow{DestinationService: ir.Service{Namespace: "default", Name: "xwing"}}},
					{Event: &ir.Flow{DestinationService: ir.Service{Namespace: "default", Name: "deathstar"}}},
					{Event: &ir.Flow{DestinationService: ir.Service{Namespace: "kube-system", Name: "kube-dns"}}},
					{Event: &ir.Flow{SourceService: ir.Service{Namespace: "kube-system", Name: "deathstar"}}},
					{Event: &ir.Flow{DestinationService: ir.Service{Namespace: "monitoring", Name: "kube-prometheus"}}},
				},
			},
			want: []bool{
				false,
				false,
				true,
				false,
				true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(t.Context(), tt.args.f, []OnBuildFilter{&ServiceFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildFilterList(t.Context(), ) error = %v, wantErr %v", err, tt.wantErr)
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
