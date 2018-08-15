// Copyright 2018 Authors of Cilium
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

package comparator

import "testing"

func TestEquals(t *testing.T) {
	type args struct {
		m1 map[string]string
		m2 map[string]string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "map is nil",
			args: args{
				m1: nil,
				m2: nil,
			},
			want: true,
		},
		{
			name: "map is equal",
			args: args{
				m1: map[string]string{
					"foo": "bar",
				},
				m2: map[string]string{
					"foo": "bar",
				},
			},
			want: true,
		},
		{
			name: "map is empty",
			args: args{
				m1: map[string]string{},
				m2: map[string]string{},
			},
			want: true,
		},
		{
			name: "map is different",
			args: args{
				m1: map[string]string{
					"fo": "bar",
				},
				m2: map[string]string{
					"foo": "bar",
				},
			},
			want: false,
		},
		{
			name: "map m1 is nil map m2 is not nil",
			args: args{
				m1: nil,
				m2: map[string]string{
					"foo": "bar",
				},
			},
			want: false,
		},
		{
			name: "map m1 is not nil map m1 is nil",
			args: args{
				m1: map[string]string{
					"foo": "bar",
				},
				m2: nil,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MapStringEquals(tt.args.m1, tt.args.m2); got != tt.want {
				t.Errorf("Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}
