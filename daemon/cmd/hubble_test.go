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

package cmd

import (
	. "gopkg.in/check.v1"
)

func (s *DaemonSuite) TestBindsLocalPort(c *C) {
	type args struct {
		addr string
	}
	tests := []struct {
		args    args
		want    bool
		wantErr bool
	}{
		{
			args: args{addr: "[::1]:4244"},
			want: true,
		},
		{
			args: args{addr: "127.0.0.1:4244"},
			want: true,
		},
		{
			args: args{addr: "localhost:4244"},
			want: true,
		},
		{
			args: args{addr: "192.168.1.1:9000"},
			want: false,
		},
		{
			args: args{addr: ":9000"},
			want: false,
		},
		{
			args: args{addr: "0.0.0.0:80"},
			want: false,
		},
		{
			args:    args{addr: " :80"},
			wantErr: true,
		},
		{
			args:    args{addr: ""},
			wantErr: true,
		},
		{
			args:    args{addr: ":"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		got, err := bindsLocalPort(tt.args.addr)
		if (err != nil) != tt.wantErr {
			c.Errorf("bindsLocalPort() error = %v, wantErr %v", err, tt.wantErr)
			return
		}
		if got != tt.want {
			c.Errorf("bindsLocalPort() got = %v, want %v", got, tt.want)
		}
	}
}
