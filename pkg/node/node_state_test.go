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

package node

import (
	"net"

	. "gopkg.in/check.v1"
)

func (s *NodeSuite) TestFindRoute(c *C) {
	_, cidr1, err := net.ParseCIDR("10.0.0.0/8")
	c.Assert(err, IsNil)

	_, cidr2, err := net.ParseCIDR("3ffe::1/48")
	c.Assert(err, IsNil)

	rt1 := route{prefix: cidr1}
	rt2 := route{prefix: cidr2}
	rt3 := route{}

	dc := newDatapathConfiguration()
	dc.routes = []route{rt1}

	c.Assert(dc.findRoute(rt1), Not(IsNil))
	c.Assert(dc.findRoute(rt2), IsNil)
	c.Assert(dc.findRoute(rt3), IsNil)
}
