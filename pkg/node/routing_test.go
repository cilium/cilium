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

	"github.com/cilium/cilium/api/v1/models"

	. "gopkg.in/check.v1"
)

func (s *NodeSuite) TestRouteEqual(c *C) {
	_, cidr1, err := net.ParseCIDR("10.0.0.0/8")
	c.Assert(err, IsNil)

	_, cidr2, err := net.ParseCIDR("3ffe::1/48")
	c.Assert(err, IsNil)

	rt1 := route{link: "foo"}
	rt2 := route{link: "foo", prefix: cidr1}
	rt3 := route{link: "foo", prefix: cidr2}
	rt4 := route{link: "foo", prefix: cidr1, via: net.ParseIP("10.1.1.1")}
	rt5 := route{link: "foo", prefix: cidr1, source: net.ParseIP("10.1.1.1")}

	c.Assert(rt1.Equal(rt1), Equals, true)
	c.Assert(rt1.Equal(rt2), Equals, false)
	c.Assert(rt1.Equal(rt3), Equals, false)
	c.Assert(rt1.Equal(rt4), Equals, false)
	c.Assert(rt1.Equal(rt5), Equals, false)

	c.Assert(rt2.Equal(rt1), Equals, false)
	c.Assert(rt2.Equal(rt2), Equals, true)
	c.Assert(rt2.Equal(rt3), Equals, false)
	c.Assert(rt2.Equal(rt4), Equals, false)
	c.Assert(rt2.Equal(rt5), Equals, false)

	c.Assert(rt3.Equal(rt1), Equals, false)
	c.Assert(rt3.Equal(rt2), Equals, false)
	c.Assert(rt3.Equal(rt3), Equals, true)
	c.Assert(rt3.Equal(rt4), Equals, false)
	c.Assert(rt3.Equal(rt5), Equals, false)

	c.Assert(rt4.Equal(rt1), Equals, false)
	c.Assert(rt4.Equal(rt2), Equals, false)
	c.Assert(rt4.Equal(rt3), Equals, false)
	c.Assert(rt4.Equal(rt4), Equals, true)
	c.Assert(rt4.Equal(rt5), Equals, false)

	c.Assert(rt5.Equal(rt1), Equals, false)
	c.Assert(rt5.Equal(rt2), Equals, false)
	c.Assert(rt5.Equal(rt3), Equals, false)
	c.Assert(rt5.Equal(rt4), Equals, false)
	c.Assert(rt5.Equal(rt5), Equals, true)
}

func (s *NodeSuite) TestEncapsulationEnabled(c *C) {
	n1 := Node{}
	n2 := Node{Routing: &models.RoutingConfiguration{}}
	n3 := Node{Routing: &models.RoutingConfiguration{Encapsulation: models.RoutingConfigurationEncapsulationDisabled}}
	n4 := Node{Routing: &models.RoutingConfiguration{Encapsulation: models.RoutingConfigurationEncapsulationGeneve}}

	c.Assert(n1.EncapsulationEnabled(), Equals, false)
	c.Assert(n2.EncapsulationEnabled(), Equals, false)
	c.Assert(n3.EncapsulationEnabled(), Equals, false)
	c.Assert(n4.EncapsulationEnabled(), Equals, true)
}

func (s *NodeSuite) TestDirectRoutingAnnounced(c *C) {
	n1 := Node{}
	n2 := Node{Routing: &models.RoutingConfiguration{}}
	n3 := Node{Routing: &models.RoutingConfiguration{DirectRouting: &models.DirectRoutingConfiguration{Announce: true}}}

	c.Assert(n1.DirectRoutingAnnounced(), Equals, false)
	c.Assert(n2.DirectRoutingAnnounced(), Equals, false)
	c.Assert(n3.DirectRoutingAnnounced(), Equals, true)
}
