// Copyright 2021 Authors of Cilium
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
