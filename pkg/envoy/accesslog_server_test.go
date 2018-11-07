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

// +build !privileged_tests

package envoy

import (
	"github.com/cilium/proxy/go/cilium/api"

	. "gopkg.in/check.v1"
)

type AccessLogServerSuite struct{}

var _ = Suite(&AccessLogServerSuite{})

func (k *AccessLogServerSuite) TestParseURL(c *C) {
	logs := []cilium.HttpLogEntry{
		{Scheme: "http", Host: "foo", Path: "/foo?blah=131"},
		{Scheme: "http", Host: "foo", Path: "foo?blah=131"},
		{Scheme: "http", Host: "foo", Path: "/foo"},
	}

	for _, l := range logs {
		u := ParseURL(l.Scheme, l.Host, l.Path)
		c.Assert(u.Scheme, Equals, "http")
		c.Assert(u.Host, Equals, "foo")
		c.Assert(u.Path, Equals, "/foo")
	}
}
