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

package xds

import (
	. "gopkg.in/check.v1"
)

type NodeSuite struct{}

var _ = Suite(&NodeSuite{})

func (s *NodeSuite) TestIstioNodeToIP(c *C) {
	var ip string
	var err error

	ip, err = IstioNodeToIP("sidecar~10.1.1.0~v0.default~default.svc.cluster.local")
	c.Assert(err, IsNil)
	c.Check(ip, Equals, "10.1.1.0")

	_, err = IstioNodeToIP("sidecar~10.1.1.0~v0.default")
	c.Assert(err, Not(IsNil))

	_, err = IstioNodeToIP("sidecar~not-an-ip~v0.default~default.svc.cluster.local")
	c.Assert(err, Not(IsNil))
}
