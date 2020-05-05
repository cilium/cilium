// Copyright 2019-2020 Authors of Cilium
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

package cmd

import (
	"net"

	. "gopkg.in/check.v1"
)

func (s *DaemonSuite) TestContainsSubnet(c *C) {
	type args struct {
		outer, inner string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			args: args{"10.10.1.2/32", "10.10.1.2/32"},
			want: true,
		},
		{
			args: args{"10.10.0.0/16", "10.10.0.1/32"},
			want: true,
		},
		{
			args: args{"10.10.0.0/16", "10.10.0.1/8"},
			want: false,
		},
		{
			args: args{"10.10.0.0/16", "10.10.255.255/16"},
			want: true,
		},
		{
			args: args{"10.10.0.0/16", "10.10.255.255/8"},
			want: false,
		},
		{
			args: args{"10.10.255.255/8", "10.10.0.0/16"},
			want: true,
		},
		{
			args: args{"0.0.0.0/0", "10.10.0.0/16"},
			want: true,
		},
		{
			args: args{"f00d::a10:0:0:0/64", "f00d::a10:0:0:1234/128"},
			want: true,
		},
		{
			args: args{"f00d::a10:0:0:1234/128", "f00d::a10:0:0:1234/64"},
			want: false,
		},
		{
			args: args{"::/0", "f00d::a10:0:0:1234/64"},
			want: true,
		},
	}
	for _, tt := range tests {
		_, outer, err := net.ParseCIDR(tt.args.outer)
		c.Assert(err, IsNil)
		_, inner, err := net.ParseCIDR(tt.args.inner)
		c.Assert(err, IsNil)
		got := containsSubnet(*outer, *inner)
		if got != tt.want {
			c.Errorf("expected containsSubnet(%q, %q) = %t, got %t",
				tt.args.outer, tt.args.inner, tt.want, got)
		}
	}
}
