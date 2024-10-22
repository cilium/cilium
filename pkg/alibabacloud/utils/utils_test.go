// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"reflect"
	"testing"
)

func TestGetENIIndexFromTags(t *testing.T) {
	type args struct {
		tags map[string]string
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "default 0",
			args: args{tags: map[string]string{}},
			want: 0,
		},
		{
			name: "index 1",
			args: args{tags: map[string]string{eniIndexTagKey: "1"}},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetENIIndexFromTags(tt.args.tags); got != tt.want {
				t.Errorf("GetENIIndexFromTags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFillTagWithENIIndex(t *testing.T) {
	type args struct {
		tags  map[string]string
		index int
	}
	tests := []struct {
		name string
		args args
		want map[string]string
	}{
		{
			name: "index 1",
			args: args{
				tags:  map[string]string{"key": "val"},
				index: 1,
			},
			want: map[string]string{"key": "val", eniIndexTagKey: "1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FillTagWithENIIndex(tt.args.tags, tt.args.index); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FillTagWithENIIndex() = %v, want %v", got, tt.want)
			}
		})
	}
}
