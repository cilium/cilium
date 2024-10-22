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

func TestWorkloadFilterInclude(t *testing.T) {
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
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{
							{
								Kind: "Deployment",
								Name: "hubble-relay",
							},
						},
					},
				},
				ev: nil,
			},
			want: false,
		},
		{
			name: "destination-nil",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{
							{
								Kind: "Deployment",
								Name: "hubble-relay",
							},
						},
					},
				},
				ev: nil,
			},
			want: false,
		},
		{
			name: "source-filter-nil",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: nil,
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			name: "destination-filter-nil",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: nil,
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			name: "source-filter-empty",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			name: "destination-filter-empty",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			// NOTE: this how we can express "at least one workload" filter
			name: "source-both-kind-and-name-empty-match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{
							{
								Kind: "",
								Name: "",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			name: "destination-both-kind-and-name-empty-match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{
							{
								Kind: "",
								Name: "",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			name: "source-both-kind-and-name-empty-mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{
							{
								Kind: "",
								Name: "",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{}},
				}},
			},
			want: false,
		},
		{
			name: "destination-both-kind-and-name-empty-mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{
							{
								Kind: "",
								Name: "",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{}},
				}},
			},
			want: false,
		},
		{
			name: "source-kind-match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{
							{
								Kind: "Deployment",
								Name: "",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			name: "destination-kind-match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{
							{
								Kind: "Deployment",
								Name: "",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			name: "source-name-match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{
							{
								Kind: "",
								Name: "hubble-relay",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			name: "destination-name-match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{
							{
								Kind: "",
								Name: "hubble-relay",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			name: "source-kind-and-name-match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{
							{
								Kind: "Deployment",
								Name: "hubble-relay",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			name: "destination-kind-and-name-match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{
							{
								Kind: "Deployment",
								Name: "hubble-relay",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: true,
		},
		{
			name: "source-kind-mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{
							{
								Kind: "ReplicatSet",
								Name: "hubble-relay",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: false,
		},
		{
			name: "destination-kind-mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{
							{
								Kind: "ReplicatSet",
								Name: "hubble-relay",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: false,
		},
		{
			name: "source-name-mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{
							{
								Kind: "Deployment",
								Name: "hubble-relay-78bcd57c9c-c4wsl",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: false,
		},
		{
			name: "destination-name-mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{
							{
								Kind: "Deployment",
								Name: "hubble-relay-78bcd57c9c-c4wsl",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: false,
		},
		{
			name: "source-kind-and-name-mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{
							{
								Kind: "ReplicatSet",
								Name: "hubble-relay-78bcd57c9c-c4wsl",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: false,
		},
		{
			name: "destination-kind-and-name-mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{
							{
								Kind: "ReplicatSet",
								Name: "hubble-relay-78bcd57c9c-c4wsl",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&WorkloadFilter{}})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, fl.MatchOne(tt.args.ev))
		})
	}
}

func TestWorkloadFilterExclude(t *testing.T) {
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
			// NOTE: this how we can express "no workload" filter
			name: "source-both-kind-and-name-empty-match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{
							{
								Kind: "",
								Name: "",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{}},
				}},
			},
			want: true,
		},
		{
			name: "destination-both-kind-and-name-empty-match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{
							{
								Kind: "",
								Name: "",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{}},
				}},
			},
			want: true,
		},
		{
			name: "source-both-kind-and-name-empty-mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceWorkload: []*flowpb.Workload{
							{
								Kind: "",
								Name: "",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: false,
		},
		{
			name: "destination-both-kind-and-name-empty-mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationWorkload: []*flowpb.Workload{
							{
								Kind: "",
								Name: "",
							},
						},
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{
						{
							Kind: "Deployment",
							Name: "hubble-relay",
						},
					}},
				}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&WorkloadFilter{}})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, fl.MatchNone(tt.args.ev))
		})
	}
}
