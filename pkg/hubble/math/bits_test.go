// Copyright 2019 Authors of Hubble
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

package math

import (
	"testing"
)

func Test_msb(t *testing.T) {
	type args struct {
		x uint64
	}
	tests := []struct {
		name string
		args args
		want uint8
	}{
		{
			args: args{
				x: 0,
			},
			want: 0,
		},
		{
			args: args{
				x: 0x10,
			},
			want: 5,
		},
		{
			args: args{
				x: 0x1FF,
			},
			want: 9,
		},
		{
			args: args{
				x: ^uint64(0),
			},
			want: 64,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MSB(tt.args.x); got != tt.want {
				t.Errorf("MSB() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getmask(t *testing.T) {
	type args struct {
		x uint8
	}
	tests := []struct {
		name string
		args args
		want uint64
	}{
		{
			args: args{
				1,
			},
			want: 0x1,
		},
		{
			args: args{
				0,
			},
			want: 0x0,
		},
		{
			args: args{
				2,
			},
			// 0011
			want: 0x3,
		},
		{
			args: args{
				3,
			},
			// 0111
			want: 0x7,
		},
		{
			args: args{
				64,
			},
			want: ^uint64(0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetMask(tt.args.x); got != tt.want {
				t.Errorf("GetMask() = %v, want %v", got, tt.want)
			}
		})
	}
}
