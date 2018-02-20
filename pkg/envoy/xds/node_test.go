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

package xds

import (
	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"

	. "gopkg.in/check.v1"
)

type NodeSuite struct{}

var _ = Suite(&NodeSuite{})

func (s *NodeSuite) TestIstioNodeToIP(c *C) {
	var node envoy_api_v2_core.Node
	var ip string
	var err error

	node.Id = "sidecar~10.1.1.0~v0.default~default.svc.cluster.local"
	ip, err = IstioNodeToIP(&node)
	c.Assert(err, IsNil)
	c.Check(ip, Equals, "10.1.1.0")

	node.Id = "sidecar~10.1.1.0~v0.default"
	ip, err = IstioNodeToIP(&node)
	c.Assert(err, Not(IsNil))

	node.Id = "sidecar~not-an-ip~v0.default~default.svc.cluster.local"
	ip, err = IstioNodeToIP(&node)
	c.Assert(err, Not(IsNil))
}
