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

package metrics

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type MetricsSuite struct{}

var _ = Suite(&MetricsSuite{})

func (s *MetricsSuite) Test_getShortPath(c *C) {
	tests := []struct {
		args string
		want string
	}{
		{
			args: "/v1/config",
			want: "/v1/config",
		},
		{
			args: "/v1/endpoint/cilium-local:0",
			want: "/v1/endpoint",
		},
		{
			args: "/v1/endpoint/container-id:597b3583727d51206d0a08df82b484925b458ff1fc04d1a98637435b73b9b47d",
			want: "/v1/endpoint",
		},
		{
			args: "/v1/endpoint/container-id:6813916d21c3311e62078a232942504937f1b4a8b2e32e40044f188da986fe41",
			want: "/v1/endpoint",
		},
		{
			args: "/v1/endpoint/container-id:cf2c692f24933fc12d51dc0b42d92708a3c73e8f3a0f517c3ed2e7628ba57d92",
			want: "/v1/endpoint",
		},
		{
			args: "/v1/healthz",
			want: "/v1/healthz",
		},
		{
			args: "/v1/ipam",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/10.16.11.109",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/10.16.169.230",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/10.16.69.17",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/f00d::a10:0:0:2f5f",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/f00d::a10:0:0:9dec",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/f00d::a10:0:0:d5c7",
			want: "/v1/ipam",
		},
		{
			args: "/v1/ipam/f00d::a10:0:0:d5c7/hello",
			want: "/v1/ipam",
		},
		{
			args: "/v1",
			want: "/v1",
		},
		{
			args: "/////",
			want: "//",
		},
		{
			args: "//",
			want: "//",
		},
		{
			args: "/",
			want: "/",
		},
		{
			args: "hello/foo/bar/",
			want: "hello/foo/bar",
		},
		{
			args: "hello/foo//",
			want: "hello/foo/",
		},
		{
			args: "hello/foo/",
			want: "hello/foo/",
		},
		{
			args: "hello/foo",
			want: "hello/foo",
		},
		{
			args: "hello/",
			want: "hello/",
		},
		{
			args: "hello",
			want: "hello",
		},
		{
			args: "",
			want: "",
		},
	}
	for _, tt := range tests {
		got := getShortPath(tt.args)
		c.Assert(got, Equals, tt.want)
	}
}
