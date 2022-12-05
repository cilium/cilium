package filters

import (
	"context"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/stretchr/testify/assert"
)

func TestHTTPHeaderFilter(t *testing.T) {

	type args struct {
		f  []*flowpb.FlowFilter
		ev []*v1.Event
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		//header filter
		{
			name: "header-nil",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HTTPHeader: []*flowpb.HTTPHeader{
							{
								Key:   "Content_Length",
								Value: "162",
							},
						},
					},
				},
				ev: nil,
			},
			want: false,
		},

		{
			name: "header-filter-nil",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HTTPHeader: nil,
					},
				},
				ev: &v1.Event{Event: &flowpb.Flow{
					HTTP: &flowpb.HTTP{
						HTTPHeader: []*flowpb.HTTPHeader{
							{
								Key:   "Content_Length",
								Value: "162",
							},
						}},
				}},
			},

			want: true,
		},

		{
			name: "header-filter-empty",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HTTPHeader: []*flowpb.HTTPHeader{},
					},
				},
			},
			ev: &v1.Event{Event: &flowpb.Flow{
				HTTP: &flowpb.HTTP{
					HTTPHeader: []*flowpb.HTTPHeader{
						{
							Key:   "Content_Length",
							Value: "162",
						},
					}},
			}},
			want: true,
		},

		{
			name: "header_key_and_value_empty_match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HTTPHeader: []*flowpb.HTTPHeader{
							Key:   "",
							Value: "",
						},
					},
				},
			},
			ev: &v1.Event{Event: &flowpb.Flow{
				HTTP: &flowpb.HTTP{
					HTTPHeader: []*flowpb.HTTPHeader{
						{
							Key:   "Content_Length",
							Value: "162",
						},
					}},
			}},
			want: true,
		},

		{
			name: "header_key_and_value_empty_match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HTTPHeader: []*flowpb.HTTPHeader{
							Key:   "",
							Value: "",
						},
					},
				},
			},
			ev: &v1.Event{Event: &flowpb.Flow{
				HTTP: &flowpb.HTTP{
					HTTPHeader: []*flowpb.HTTPHeader{}},
			}},
			want: false,
		},

		{
			name: "header_key_match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HTTPHeader: []*flowpb.HTTPHeader{
							Key:   "Content_Length",
							Value: "",
						},
					},
				},
			},
			ev: &v1.Event{Event: &flowpb.Flow{
				HTTP: &flowpb.HTTP{
					HTTPHeader: []*flowpb.HTTPHeader{
						{
							Key:   "Content_Length",
							Value: "162",
						},
					}},
			}},
			want: true,
		},

		{
			name: "header_value_match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HTTPHeader: []*flowpb.HTTPHeader{
							Key:   "",
							Value: "162",
						},
					},
				},
			},
			ev: &v1.Event{Event: &flowpb.Flow{
				HTTP: &flowpb.HTTP{
					HTTPHeader: []*flowpb.HTTPHeader{
						{
							Key:   "Content_Length",
							Value: "162",
						},
					}},
			}},
			want: true,
		},

		{
			name: "header_key_and_value_match",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HTTPHeader: []*flowpb.HTTPHeader{
							Key:   "Content_Length",
							Value: "162",
						},
					},
				},
			},
			ev: &v1.Event{Event: &flowpb.Flow{
				HTTP: &flowpb.HTTP{
					HTTPHeader: []*flowpb.HTTPHeader{
						{
							Key:   "Content_Length",
							Value: "162",
						},
					}},
			}},
			want: true,
		},

		{
			name: "header_key_mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HTTPHeader: []*flowpb.HTTPHeader{
							Key:   "Connection",
							Value: "162",
						},
					},
				},
			},
			ev: &v1.Event{Event: &flowpb.Flow{
				HTTP: &flowpb.HTTP{
					HTTPHeader: []*flowpb.HTTPHeader{
						{
							Key:   "Content_Length",
							Value: "162",
						},
					}},
			}},
			want: false,
		},

		{
			name: "header_value_mismatch",
			args: args{
				f: []*flowpb.FlowFilter{
					{
						HTTPHeader: []*flowpb.HTTPHeader{
							Key:   "Content_Length",
							Value: "16200",
						},
					},
				},
			},
			ev: &v1.Event{Event: &flowpb.Flow{
				HTTP: &flowpb.HTTP{
					HTTPHeader: []*flowpb.HTTPHeader{
						{
							Key:   "Content_Length",
							Value: "162",
						},
					}},
			}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(context.Background(), tt.args.f, []OnBuildFilter{&HTTPHeaderFilter{}})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, fl.MatchOne(tt.args.ev))
		})
	}

}
