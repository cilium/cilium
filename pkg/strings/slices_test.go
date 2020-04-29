// Copyright 2020 Authors of Cilium
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

package strings

import (
	"testing"
)

func TestEqualStrings(t *testing.T) {
	type args struct {
		a []string
		b []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "test-1",
			args: args{
				a: nil,
				b: nil,
			},
			want: true,
		},
		{
			name: "test-2",
			args: args{
				a: []string{""},
				b: nil,
			},
			want: false,
		},
		{
			name: "test-3",
			args: args{
				a: nil,
				b: []string{"foo"},
			},
			want: false,
		},
		{
			name: "test-4",
			args: args{
				a: []string{"foo"},
				b: []string{"foo"},
			},
			want: true,
		},
		{
			name: "test-5",
			args: args{
				a: []string{"bar", "foo"},
				b: []string{"foo", "bar"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EqualStrings(tt.args.a, tt.args.b); got != tt.want {
				t.Errorf("EqualStrings() = %v, want %v", got, tt.want)
			}
		})
	}
}
