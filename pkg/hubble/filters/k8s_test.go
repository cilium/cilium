// Copyright 2019-2020 Authors of Hubble
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

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestPodFilter(t *testing.T) {
	type args struct {
		f  []*pb.FlowFilter
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
				f: []*pb.FlowFilter{
					{SourcePod: []string{"xwing", "default/tiefighter"}},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{Source: &pb.Endpoint{Namespace: "default", PodName: "xwing"}}},
					{Event: &pb.Flow{Source: &pb.Endpoint{Namespace: "default", PodName: "tiefighter"}}},
					{Event: &pb.Flow{Source: &pb.Endpoint{Namespace: "kube-system", PodName: "xwing"}}},
					{Event: &pb.Flow{Destination: &pb.Endpoint{Namespace: "default", PodName: "xwing"}}},
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
				f: []*pb.FlowFilter{
					{DestinationPod: []string{"xwing", "default/tiefighter"}},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{Destination: &pb.Endpoint{Namespace: "default", PodName: "xwing"}}},
					{Event: &pb.Flow{Destination: &pb.Endpoint{Namespace: "default", PodName: "tiefighter"}}},
					{Event: &pb.Flow{Destination: &pb.Endpoint{Namespace: "kube-system", PodName: "xwing"}}},
					{Event: &pb.Flow{Source: &pb.Endpoint{Namespace: "default", PodName: "xwing"}}},
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
				f: []*pb.FlowFilter{
					{
						SourcePod:      []string{"xwing", "tiefighter"},
						DestinationPod: []string{"deathstar"},
					},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "default", PodName: "xwing"},
						Destination: &pb.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &pb.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "default", PodName: "deathstar"},
						Destination: &pb.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &pb.Endpoint{Namespace: "default", PodName: "xwing"},
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
				f: []*pb.FlowFilter{
					{SourcePod: []string{"xwing"}},
					{DestinationPod: []string{"deathstar"}},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "default", PodName: "xwing"},
						Destination: &pb.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &pb.Endpoint{Namespace: "default", PodName: "deathstar"},
					}},
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "default", PodName: "deathstar"},
						Destination: &pb.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &pb.Endpoint{Namespace: "default", PodName: "xwing"},
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
				f: []*pb.FlowFilter{
					{SourcePod: []string{"kube-system/"}},
					{DestinationPod: []string{"kube-system/"}},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "kube-system", PodName: "coredns"},
						Destination: &pb.Endpoint{Namespace: "kube-system", PodName: "kube-proxy"},
					}},
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &pb.Endpoint{Namespace: "kube-system", PodName: "coredns"},
					}},
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "kube-system", PodName: "coredns"},
						Destination: &pb.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &pb.Flow{
						Source:      &pb.Endpoint{Namespace: "default", PodName: "tiefighter"},
						Destination: &pb.Endpoint{Namespace: "default", PodName: "xwing"},
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
				f: []*pb.FlowFilter{
					{SourcePod: []string{"xwing", "kube-system/coredns-"}},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{
						Source: &pb.Endpoint{Namespace: "default", PodName: "xwing"},
					}},
					{Event: &pb.Flow{
						Source: &pb.Endpoint{Namespace: "default", PodName: "xwing-t-65b"},
					}},
					{Event: &pb.Flow{
						Source: &pb.Endpoint{Namespace: "kube-system", PodName: "coredns-12345"},
					}},
					{Event: &pb.Flow{
						Source: &pb.Endpoint{Namespace: "kube-system", PodName: "-coredns-12345"},
					}},
					{Event: &pb.Flow{
						Source: &pb.Endpoint{Namespace: "default", PodName: "tiefighter"},
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
				f: []*pb.FlowFilter{
					{SourcePod: []string{"xwing"}},
				},
				ev: []*v1.Event{
					nil,
					{},
					{Event: &pb.Flow{}},
					{Event: &pb.Flow{Source: &pb.Endpoint{Namespace: "", PodName: "xwing"}}},
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
				f: []*pb.FlowFilter{
					{SourcePod: []string{""}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid destination pod filter",
			args: args{
				f: []*pb.FlowFilter{
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
		f  []*pb.FlowFilter
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
				f: []*pb.FlowFilter{
					{SourceService: []string{"deathstar", "kube-system/kube-dns"}},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{SourceService: &pb.Service{Namespace: "default", Name: "xwing"}}},
					{Event: &pb.Flow{SourceService: &pb.Service{Namespace: "default", Name: "deathstar"}}},
					{Event: &pb.Flow{SourceService: &pb.Service{Namespace: "kube-system", Name: "kube-dns"}}},
					{Event: &pb.Flow{DestinationService: &pb.Service{Namespace: "kube-system", Name: "deathstar"}}},
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
				f: []*pb.FlowFilter{
					{DestinationService: []string{"default/", "kube-system/kube-"}},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{DestinationService: &pb.Service{Namespace: "default", Name: "xwing"}}},
					{Event: &pb.Flow{DestinationService: &pb.Service{Namespace: "default", Name: "deathstar"}}},
					{Event: &pb.Flow{DestinationService: &pb.Service{Namespace: "kube-system", Name: "kube-dns"}}},
					{Event: &pb.Flow{SourceService: &pb.Service{Namespace: "kube-system", Name: "deathstar"}}},
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
