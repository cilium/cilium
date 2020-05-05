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

	"github.com/stretchr/testify/assert"
)

func TestFQDNFilter(t *testing.T) {
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
			name: "source fqdn",
			args: args{
				f: []*pb.FlowFilter{
					{SourceFqdn: []string{"cilium.io", "ebpf.io"}},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{SourceNames: []string{"cilium.io"}}},
					{Event: &pb.Flow{SourceNames: []string{"ebpf.io"}}},
					{Event: &pb.Flow{DestinationNames: []string{"cilium.io"}}},
					{Event: &pb.Flow{DestinationNames: []string{"ebpf.io"}}},
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
			name: "destination fqdn",
			args: args{
				f: []*pb.FlowFilter{
					{DestinationFqdn: []string{"cilium.io", "ebpf.io"}},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{SourceNames: []string{"cilium.io"}}},
					{Event: &pb.Flow{SourceNames: []string{"ebpf.io"}}},
					{Event: &pb.Flow{DestinationNames: []string{"cilium.io"}}},
					{Event: &pb.Flow{DestinationNames: []string{"ebpf.io"}}},
				},
			},
			want: []bool{
				false,
				false,
				true,
				true,
			},
		},
		{
			name: "source and destination fqdn",
			args: args{
				f: []*pb.FlowFilter{
					{
						SourceFqdn:      []string{"cilium.io", "docs.cilium.io"},
						DestinationFqdn: []string{"ebpf.io"},
					},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{
						SourceNames:      []string{"cilium.io"},
						DestinationNames: []string{"ebpf.io"},
					}},
					{Event: &pb.Flow{
						SourceNames:      []string{"ebpf.io"},
						DestinationNames: []string{"cilium.io"},
					}},
					{Event: &pb.Flow{
						SourceNames:      []string{"deathstar.empire.svc.cluster.local", "docs.cilium.io"},
						DestinationNames: []string{"ebpf.io"},
					}},
				},
			},
			want: []bool{
				true,
				false,
				true,
			},
		},
		{
			name: "source or destination fqdn",
			args: args{
				f: []*pb.FlowFilter{
					{SourceFqdn: []string{"cilium.io", "docs.cilium.io"}},
					{DestinationFqdn: []string{"ebpf.io"}},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{
						SourceNames:      []string{"cilium.io"},
						DestinationNames: []string{"ebpf.io"},
					}},
					{Event: &pb.Flow{
						SourceNames:      []string{"ebpf.io"},
						DestinationNames: []string{"cilium.io"},
					}},
					{Event: &pb.Flow{
						SourceNames: []string{"deathstar.empire.svc.cluster.local", "docs.cilium.io"},
					}},
					{Event: &pb.Flow{
						DestinationNames: []string{"ebpf.io"},
					}},
					{Event: &pb.Flow{
						SourceNames:      []string{"deathstar.empire.svc.cluster.local", "docs.cilium.io"},
						DestinationNames: []string{"ebpf.io"},
					}},
				},
			},
			want: []bool{
				true,
				false,
				true,
				true,
				true,
			},
		},
		{
			name: "invalid data",
			args: args{
				f: []*pb.FlowFilter{
					{SourceFqdn: []string{"cilium.io."}},
				},
				ev: []*v1.Event{
					nil,
					{},
					{Event: &pb.Flow{}},
					{Event: &pb.Flow{SourceNames: []string{"cilium.io."}}}, // should not have trailing dot
					{Event: &pb.Flow{SourceNames: []string{"www.cilium.io"}}},
					{Event: &pb.Flow{SourceNames: []string{""}}},
				},
			},
			want: []bool{
				false,
				false,
				false,
				false,
				false,
				false,
			},
		},
		{
			name: "invalid source fqdn filter",
			args: args{
				f: []*pb.FlowFilter{
					{SourceFqdn: []string{""}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid destination fqdn filter",
			args: args{
				f: []*pb.FlowFilter{
					{DestinationFqdn: []string{"."}},
				},
			},
			wantErr: true,
		},
		{
			name: "wildcard filters",
			args: args{
				f: []*pb.FlowFilter{
					{SourceFqdn: []string{"*.cilium.io", "*.org."}},
					{DestinationFqdn: []string{"*"}},
				},
				ev: []*v1.Event{
					{Event: &pb.Flow{SourceNames: []string{"www.cilium.io"}}},
					{Event: &pb.Flow{SourceNames: []string{"multiple.domains.org"}}},
					{Event: &pb.Flow{SourceNames: []string{"cilium.io"}}},
					{Event: &pb.Flow{SourceNames: []string{"tiefighter", "empire.org"}}},
					{Event: &pb.Flow{DestinationNames: []string{}}},
					{Event: &pb.Flow{DestinationNames: []string{"anything.really"}}},
					{Event: &pb.Flow{DestinationNames: []string{""}}},
				},
			},
			want: []bool{
				true,
				true,
				false,
				true,
				false,
				true,
				true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&FQDNFilter{}})
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

func Test_filterByDNSQuery(t *testing.T) {
	type args struct {
		f  []*pb.FlowFilter
		ev *v1.Event
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    bool
	}{
		{
			name: "not-dns",
			args: args{
				f:  []*pb.FlowFilter{{DnsQuery: []string{".*"}}},
				ev: &v1.Event{Event: &pb.Flow{}},
			},
			wantErr: false,
			want:    false,
		},
		{
			name: "invalid-regex",
			args: args{
				f: []*pb.FlowFilter{{DnsQuery: []string{"*"}}},
			},
			wantErr: true,
		},
		{
			name: "positive",
			args: args{
				f: []*pb.FlowFilter{{DnsQuery: []string{".*\\.com$", ".*\\.io"}}},
				ev: &v1.Event{Event: &pb.Flow{
					L7: &pb.Layer7{
						Record: &pb.Layer7_Dns{
							Dns: &pb.DNS{
								Query: "cilium.io",
							},
						},
					},
				}},
			},
			want: true,
		},
		{
			name: "positive",
			args: args{
				f: []*pb.FlowFilter{{DnsQuery: []string{".*\\.com$", ".*\\.io"}}},
				ev: &v1.Event{Event: &pb.Flow{
					L7: &pb.Layer7{
						Record: &pb.Layer7_Dns{
							Dns: &pb.DNS{
								Query: "cilium.io",
							},
						},
					},
				}},
			},
			wantErr: false,
			want:    true,
		},
		{
			name: "negative",
			args: args{
				f: []*pb.FlowFilter{{DnsQuery: []string{".*\\.com$", ".*\\.net"}}},
				ev: &v1.Event{Event: &pb.Flow{
					L7: &pb.Layer7{
						Record: &pb.Layer7_Dns{
							Dns: &pb.DNS{
								Query: "cilium.io",
							},
						},
					},
				}},
			},
			wantErr: false,
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&FQDNFilter{}})
			assert.Equal(t, tt.wantErr, err != nil)
			if err == nil {
				got := fl.MatchOne(tt.args.ev)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
