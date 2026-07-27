// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func Test_filterByEncrypted(t *testing.T) {
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
			name: "nil flow",
			args: args{
				f:  []*flowpb.FlowFilter{{Encrypted: []bool{true}}},
				ev: &v1.Event{},
			},
			want: false,
		},
		{
			name: "empty-param",
			args: args{
				f:  []*flowpb.FlowFilter{{Encrypted: []bool{}}},
				ev: &v1.Event{Event: &flowpb.Flow{IP: &flowpb.IP{Encrypted: true}}},
			},
			want: true,
		},
		{
			name: "empty-param-unencrypted",
			args: args{
				f:  []*flowpb.FlowFilter{{Encrypted: []bool{}}},
				ev: &v1.Event{Event: &flowpb.Flow{IP: &flowpb.IP{Encrypted: false}}},
			},
			want: true,
		},
		{
			name: "encrypted-flow-match",
			args: args{
				f:  []*flowpb.FlowFilter{{Encrypted: []bool{true}}},
				ev: &v1.Event{Event: &flowpb.Flow{IP: &flowpb.IP{Encrypted: true}}},
			},
			want: true,
		},
		{
			name: "encrypted-flow-no-match",
			args: args{
				f:  []*flowpb.FlowFilter{{Encrypted: []bool{true}}},
				ev: &v1.Event{Event: &flowpb.Flow{IP: &flowpb.IP{Encrypted: false}}},
			},
			want: false,
		},
		{
			name: "unencrypted-flow-match",
			args: args{
				f:  []*flowpb.FlowFilter{{Encrypted: []bool{false}}},
				ev: &v1.Event{Event: &flowpb.Flow{IP: &flowpb.IP{Encrypted: false}}},
			},
			want: true,
		},
		{
			name: "unencrypted-flow-no-match",
			args: args{
				f:  []*flowpb.FlowFilter{{Encrypted: []bool{false}}},
				ev: &v1.Event{Event: &flowpb.Flow{IP: &flowpb.IP{Encrypted: true}}},
			},
			want: false,
		},
		{
			name: "multiple-values-match-encrypted",
			args: args{
				f:  []*flowpb.FlowFilter{{Encrypted: []bool{true, false}}},
				ev: &v1.Event{Event: &flowpb.Flow{IP: &flowpb.IP{Encrypted: true}}},
			},
			want: true,
		},
		{
			name: "multiple-values-match-unencrypted",
			args: args{
				f:  []*flowpb.FlowFilter{{Encrypted: []bool{true, false}}},
				ev: &v1.Event{Event: &flowpb.Flow{IP: &flowpb.IP{Encrypted: false}}},
			},
			want: true,
		},
		{
			name: "nil-ip-field",
			args: args{
				f:  []*flowpb.FlowFilter{{Encrypted: []bool{true}}},
				ev: &v1.Event{Event: &flowpb.Flow{IP: nil}},
			},
			want: false,
		},
		{
			name: "default-unencrypted",
			args: args{
				f:  []*flowpb.FlowFilter{{Encrypted: []bool{false}}},
				ev: &v1.Event{Event: &flowpb.Flow{IP: &flowpb.IP{}}},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl, err := BuildFilterList(t.Context(), tt.args.f, []OnBuildFilter{&EncryptedFilter{}})
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
