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

func TestFQDNFilter(t *testing.T) {
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
			name: "source fqdn",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourceFqdn: []string{"cilium.io", "ebpf.io"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{SourceNames: []string{"cilium.io"}}},
					{Event: &flowpb.Flow{SourceNames: []string{"ebpf.io"}}},
					{Event: &flowpb.Flow{DestinationNames: []string{"cilium.io"}}},
					{Event: &flowpb.Flow{DestinationNames: []string{"ebpf.io"}}},
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
				f: []*flowpb.FlowFilter{
					{DestinationFqdn: []string{"cilium.io", "ebpf.io"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{SourceNames: []string{"cilium.io"}}},
					{Event: &flowpb.Flow{SourceNames: []string{"ebpf.io"}}},
					{Event: &flowpb.Flow{DestinationNames: []string{"cilium.io"}}},
					{Event: &flowpb.Flow{DestinationNames: []string{"ebpf.io"}}},
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
				f: []*flowpb.FlowFilter{
					{
						SourceFqdn:      []string{"cilium.io", "docs.cilium.io"},
						DestinationFqdn: []string{"ebpf.io"},
					},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{
						SourceNames:      []string{"cilium.io"},
						DestinationNames: []string{"ebpf.io"},
					}},
					{Event: &flowpb.Flow{
						SourceNames:      []string{"ebpf.io"},
						DestinationNames: []string{"cilium.io"},
					}},
					{Event: &flowpb.Flow{
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
				f: []*flowpb.FlowFilter{
					{SourceFqdn: []string{"cilium.io", "docs.cilium.io"}},
					{DestinationFqdn: []string{"ebpf.io"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{
						SourceNames:      []string{"cilium.io"},
						DestinationNames: []string{"ebpf.io"},
					}},
					{Event: &flowpb.Flow{
						SourceNames:      []string{"ebpf.io"},
						DestinationNames: []string{"cilium.io"},
					}},
					{Event: &flowpb.Flow{
						SourceNames: []string{"deathstar.empire.svc.cluster.local", "docs.cilium.io"},
					}},
					{Event: &flowpb.Flow{
						DestinationNames: []string{"ebpf.io"},
					}},
					{Event: &flowpb.Flow{
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
				f: []*flowpb.FlowFilter{
					{SourceFqdn: []string{"cilium.io."}},
				},
				ev: []*v1.Event{
					nil,
					{},
					{Event: &flowpb.Flow{}},
					{Event: &flowpb.Flow{SourceNames: []string{"cilium.io."}}}, // should not have trailing dot
					{Event: &flowpb.Flow{SourceNames: []string{"www.cilium.io"}}},
					{Event: &flowpb.Flow{SourceNames: []string{""}}},
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
				f: []*flowpb.FlowFilter{
					{SourceFqdn: []string{""}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid destination fqdn filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{DestinationFqdn: []string{"."}},
				},
			},
			wantErr: true,
		},
		{
			name: "wildcard filters",
			args: args{
				f: []*flowpb.FlowFilter{
					{SourceFqdn: []string{"*.cilium.io", "*.org."}},
					{DestinationFqdn: []string{"*"}},
				},
				ev: []*v1.Event{
					{Event: &flowpb.Flow{SourceNames: []string{"www.cilium.io"}}},
					{Event: &flowpb.Flow{SourceNames: []string{"multiple.domains.org"}}},
					{Event: &flowpb.Flow{SourceNames: []string{"cilium.io"}}},
					{Event: &flowpb.Flow{SourceNames: []string{"tiefighter", "empire.org"}}},
					{Event: &flowpb.Flow{DestinationNames: []string{}}},
					{Event: &flowpb.Flow{DestinationNames: []string{"anything.really"}}},
					{Event: &flowpb.Flow{DestinationNames: []string{""}}},
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
				t.Errorf("BuildFilterList() with FQDNFilter: error = %v, wantErr %v", err, tt.wantErr)
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
		f  []*flowpb.FlowFilter
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
				f:  []*flowpb.FlowFilter{{DnsQuery: []string{".*"}}},
				ev: &v1.Event{Event: &flowpb.Flow{}},
			},
			wantErr: false,
			want:    false,
		},
		{
			name: "invalid-regex",
			args: args{
				f: []*flowpb.FlowFilter{{DnsQuery: []string{"*"}}},
			},
			wantErr: true,
		},
		{
			name: "positive",
			args: args{
				f: []*flowpb.FlowFilter{{DnsQuery: []string{".*\\.com$", ".*\\.io"}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L7: &flowpb.Layer7{
						Record: &flowpb.Layer7_Dns{
							Dns: &flowpb.DNS{
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
				f: []*flowpb.FlowFilter{{DnsQuery: []string{".*\\.com$", ".*\\.io"}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L7: &flowpb.Layer7{
						Record: &flowpb.Layer7_Dns{
							Dns: &flowpb.DNS{
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
				f: []*flowpb.FlowFilter{{DnsQuery: []string{".*\\.com$", ".*\\.net"}}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L7: &flowpb.Layer7{
						Record: &flowpb.Layer7_Dns{
							Dns: &flowpb.DNS{
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
