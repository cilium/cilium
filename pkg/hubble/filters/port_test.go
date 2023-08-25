// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestPortFilter(t *testing.T) {
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
			name: "udp",
			args: args{
				f: []*flowpb.FlowFilter{{
					SourcePort:      []string{"12345"},
					DestinationPort: []string{"53"},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{
						SourcePort:      12345,
						DestinationPort: 53,
					}}},
				}},
			},
			want: true,
		},
		{
			name: "tcp",
			args: args{
				f: []*flowpb.FlowFilter{{
					SourcePort:      []string{"32320"},
					DestinationPort: []string{"80"},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
						SourcePort:      32320,
						DestinationPort: 80,
					}}},
				}},
			},
			want: true,
		},
		{
			name: "wrong direction",
			args: args{
				f: []*flowpb.FlowFilter{{
					DestinationPort: []string{"80"},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
						SourcePort:      80,
						DestinationPort: 32320,
					}}},
				}},
			},
			want: false,
		},
		{
			name: "no port",
			args: args{
				f: []*flowpb.FlowFilter{{
					DestinationPort: []string{"0"},
				}},
				ev: &v1.Event{Event: &flowpb.Flow{
					L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_ICMPv4{ICMPv4: &flowpb.ICMPv4{}}},
				}},
			},
			want: false,
		},
		{
			name: "invalid port",
			args: args{
				f: []*flowpb.FlowFilter{{SourcePort: []string{"999999"}}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&PortFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("\"%s\" error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got := fl.MatchOne(tt.args.ev); got != tt.want {
				t.Errorf("\"%s\" got %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
