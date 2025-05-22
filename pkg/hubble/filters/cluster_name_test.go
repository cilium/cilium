// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestClusterNameFilter(t *testing.T) {
	tt := []struct {
		name    string
		f       []*flowpb.FlowFilter
		ev      []*v1.Event
		wantErr bool
		want    []bool
	}{
		{
			name: "source cluster",
			f: []*flowpb.FlowFilter{
				{SourceClusterName: []string{"aws-south-1", "gke-europe-west1-c"}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{Source: &flowpb.Endpoint{ClusterName: "aws-south-1"}}},
				{Event: &flowpb.Flow{Source: &flowpb.Endpoint{ClusterName: "gke-europe-west1-c"}}},
				{Event: &flowpb.Flow{}},
				{Event: &flowpb.Flow{Source: &flowpb.Endpoint{ClusterName: "aks-eastus2-1"}}},
				{Event: &flowpb.Flow{Destination: &flowpb.Endpoint{ClusterName: "gke-europe-west1-c"}}},
			},
			want: []bool{
				true,
				true,
				false,
				false,
				false,
			},
		},
		{
			name: "destination cluster",
			f: []*flowpb.FlowFilter{
				{DestinationClusterName: []string{"aws-south-1", "gke-europe-west1-c"}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{Destination: &flowpb.Endpoint{ClusterName: "aws-south-1"}}},
				{Event: &flowpb.Flow{Destination: &flowpb.Endpoint{ClusterName: "gke-europe-west1-c"}}},
				{Event: &flowpb.Flow{}},
				{Event: &flowpb.Flow{Destination: &flowpb.Endpoint{ClusterName: "aks-eastus2-1"}}},
				{Event: &flowpb.Flow{Source: &flowpb.Endpoint{ClusterName: "gke-europe-west1-c"}}},
			},
			want: []bool{
				true,
				true,
				false,
				false,
				false,
			},
		},
		{
			name: "source and destination cluster",
			f: []*flowpb.FlowFilter{
				{
					SourceClusterName:      []string{"aws-south-1", "gke-europe-west1-c"},
					DestinationClusterName: []string{"aks-eastus2-1"},
				},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{
					Source:      &flowpb.Endpoint{ClusterName: "aws-south-1"},
					Destination: &flowpb.Endpoint{ClusterName: "aks-eastus2-1"},
				}},
				{Event: &flowpb.Flow{
					Source:      &flowpb.Endpoint{ClusterName: "gke-europe-west1-c"},
					Destination: &flowpb.Endpoint{ClusterName: "aks-eastus2-1"},
				}},
				{Event: &flowpb.Flow{
					Source:      &flowpb.Endpoint{ClusterName: "default"},
					Destination: &flowpb.Endpoint{ClusterName: "aks-eastus2-1"},
				}},
				{Event: &flowpb.Flow{
					Source:      &flowpb.Endpoint{ClusterName: "aks-eastus2-1"},
					Destination: &flowpb.Endpoint{ClusterName: "aws-south-1"},
				}},
				{Event: &flowpb.Flow{
					Source:      &flowpb.Endpoint{ClusterName: "aks-eastus2-1"},
					Destination: &flowpb.Endpoint{ClusterName: "gke-europe-west1-c"},
				}},
				{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{ClusterName: "default"},
				}},
			},
			want: []bool{
				true,
				true,
				false,
				false,
				false,
				false,
			},
		},
		{
			name: "source or destination cluster",
			f: []*flowpb.FlowFilter{
				{SourceClusterName: []string{"aws-south-1", "gke-europe-west1-c"}},
				{DestinationClusterName: []string{"aks-eastus2-1"}},
			},
			ev: []*v1.Event{
				{Event: &flowpb.Flow{
					Source:      &flowpb.Endpoint{ClusterName: "aws-south-1"},
					Destination: &flowpb.Endpoint{ClusterName: "default"},
				}},
				{Event: &flowpb.Flow{
					Source:      &flowpb.Endpoint{ClusterName: "gke-europe-west1-c"},
					Destination: &flowpb.Endpoint{ClusterName: "default"},
				}},
				{Event: &flowpb.Flow{
					Source:      &flowpb.Endpoint{ClusterName: "default"},
					Destination: &flowpb.Endpoint{ClusterName: "aks-eastus2-1"},
				}},
				{Event: &flowpb.Flow{
					Source:      &flowpb.Endpoint{ClusterName: "aks-eastus2-1"},
					Destination: &flowpb.Endpoint{ClusterName: "aws-south-1"},
				}},
				{Event: &flowpb.Flow{
					Source:      &flowpb.Endpoint{ClusterName: "aks-eastus2-1"},
					Destination: &flowpb.Endpoint{ClusterName: "gke-europe-west1-c"},
				}},
				{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{ClusterName: "default"},
				}},
			},
			want: []bool{
				true,
				true,
				true,
				false,
				false,
				false,
			},
		},
		{
			name: "invalid data",
			f: []*flowpb.FlowFilter{
				{SourceClusterName: []string{"aws-south-1"}},
			},
			ev: []*v1.Event{
				nil,
				{},
				{Event: &flowpb.Flow{}},
				{Event: &flowpb.Flow{Source: &flowpb.Endpoint{ClusterName: ""}}},
			},
			want: []bool{
				false,
				false,
				false,
				false,
			},
		},
		{
			name: "invalid source cluster filter",
			f: []*flowpb.FlowFilter{
				{SourceClusterName: []string{""}},
			},
			wantErr: true,
		},
		{
			name: "invalid destination cluster filter",
			f: []*flowpb.FlowFilter{
				{DestinationClusterName: []string{""}},
			},
			wantErr: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			fl, err := BuildFilterList(t.Context(), tc.f, []OnBuildFilter{&ClusterNameFilter{}})
			if (err != nil) != tc.wantErr {
				t.Errorf("BuildFilterList(t.Context(), ) error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			for i, ev := range tc.ev {
				if filterResult := fl.MatchOne(ev); filterResult != tc.want[i] {
					t.Errorf("\"%s\" filterResult %d = %v, want %v", tc.name, i, filterResult, tc.want[i])
				}
			}
		})
	}
}
