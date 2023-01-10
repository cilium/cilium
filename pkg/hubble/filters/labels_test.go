// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"reflect"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func TestLabelSelectorFilter(t *testing.T) {
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
			name: "label filter without value",
			args: args{
				f: []*flowpb.FlowFilter{{SourceLabel: []string{"label1", "label2"}}},
				ev: []*v1.Event{
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label1"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label1=val1"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label2", "label3", "label4=val4"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label3"},
							},
						},
					},
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
			name: "label filter with value",
			args: args{
				f: []*flowpb.FlowFilter{{SourceLabel: []string{"label1=val1", "label2=val2"}}},
				ev: []*v1.Event{
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label1"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label1=val1"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label1=val2", "label2=val1", "label3"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label2=val2", "label3"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label3=val1"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{""},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: nil,
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label1=val1=toomuch"},
							},
						},
					},
				},
			},
			want: []bool{
				false,
				true,
				false,
				true,
				false,
				false,
				false,
				false,
			},
		},
		{
			name: "complex label label filter",
			args: args{
				f: []*flowpb.FlowFilter{{SourceLabel: []string{"label1 in (val1, val2), label3 notin ()"}}},
				ev: []*v1.Event{
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label1"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label1=val1"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label1=val2", "label2=val1", "label3=val3"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label2=val2", "label3"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label1=val1", "label3=val3"},
							},
						},
					},
				},
			},
			want: []bool{
				false,
				true,
				true,
				false,
				true,
			},
		},
		{
			name: "source and destination label filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceLabel:      []string{"src1, src2=val2"},
						DestinationLabel: []string{"dst1, dst2=val2"},
					},
				},
				ev: []*v1.Event{
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"src1", "src2=val2"},
							},
							Destination: &flowpb.Endpoint{
								Labels: []string{"dst1", "dst2=val2"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"label1=val1"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Destination: &flowpb.Endpoint{
								Labels: []string{"dst1", "dst2=val2"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"dst1", "dst2=val2"},
							},
							Destination: &flowpb.Endpoint{
								Labels: []string{"src1", "src2=val2"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"src1"},
							},
							Destination: &flowpb.Endpoint{
								Labels: []string{"dst1"},
							},
						},
					},
				},
			},
			want: []bool{
				true,
				false,
				false,
				false,
				false,
			},
		},
		{
			name: "matchall filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceLabel: []string{""},
					},
				},
				ev: []*v1.Event{
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"src1", "src2=val2"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: nil,
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{""},
							},
						},
					},
				},
			},
			want: []bool{
				true,
				true,
				true,
			},
		},
		{
			name: "cilium fixed prefix filters",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceLabel: []string{"k8s:app=bar", "foo", "reserved:host"},
					},
				},
				ev: []*v1.Event{
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"k8s:app=bar"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"k8s:foo=baz"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"k8s.app=bar"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"container:foo=bar", "reserved:host"},
							},
						},
					},
				},
			},
			want: []bool{
				true,
				true,
				false,
				true,
			},
		},
		{
			name: "cilium any prefix filters",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceLabel: []string{"any:key"},
					},
				},
				ev: []*v1.Event{
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"key"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"reserved:key"},
							},
						},
					},
					{
						Event: &flowpb.Flow{
							Source: &flowpb.Endpoint{
								Labels: []string{"any.key"},
							},
						},
					},
				},
			},
			want: []bool{
				true,
				true,
				false,
			},
		},
		{
			name: "invalid source filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						SourceLabel: []string{"()"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid destination filter",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						DestinationLabel: []string{"="},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&LabelsFilter{}})
			if (err != nil) != tt.wantErr {
				t.Errorf("\"%s\" error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}
			if err != nil {
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

func Test_parseSelector(t *testing.T) {
	type args struct {
		selector string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "simple labels",
			args: args{
				selector: "bar=baz,k8s:app=hubble,reserved:world",
			},
			want: "bar=baz,k8s.app=hubble,reserved.world",
		},
		{
			name: "complex labels",
			args: args{
				selector: "any:dash-label.com,k8s:io.cilium in (is-awesome,rocks)",
			},
			want: "any.dash-label.com,k8s.io.cilium in (is-awesome,rocks)",
		},
		{
			name: "too many colons",
			args: args{
				selector: "any:k8s:bla",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSelector(tt.args.selector)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSelector() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got.String(), tt.want) {
				t.Errorf("parseSelector() = %v, want %v", got, tt.want)
			}
		})
	}
}
