// Copyright 2019 Authors of Cilium
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

package lbmap

import (
	"testing"
)

func Test_createSvcFlag(t *testing.T) {
	type args struct {
		externalIPs bool
	}
	tests := []struct {
		name string
		args args
		want uint8
	}{
		{
			args: args{
				externalIPs: false,
			},
			want: 0,
		},
		{
			args: args{
				externalIPs: true,
			},
			want: 0x01,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createSvcFlag(tt.args.externalIPs); got != tt.want {
				t.Errorf("createSvcFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hasExternalIPsSet(t *testing.T) {
	type args struct {
		flags uint8
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			args: args{flags: createSvcFlag(true)},
			want: true,
		},
		{
			args: args{flags: createSvcFlag(false)},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasExternalIPsSet(tt.args.flags); got != tt.want {
				t.Errorf("hasExternalIPsSet() = %v, want %v", got, tt.want)
			}
		})
	}
}
