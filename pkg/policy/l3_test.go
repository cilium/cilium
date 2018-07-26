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

package policy

import (
	"net"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"

	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) SetUpTest(c *C) {
	_, v6node, err := net.ParseCIDR("2001:DB8::/96")
	c.Assert(err, IsNil)
	_, v4node, err := net.ParseCIDR("192.0.2.3/24")
	c.Assert(err, IsNil)
	err = node.SetIPv6NodeRange(v6node)
	c.Assert(err, IsNil)
	node.SetIPv4AllocRange(v4node)
}

func (ds *PolicyTestSuite) TearDownTest(c *C) {
	node.Uninitialize()
}

func populateMap(m *CIDRPolicyMap) {
	lbls := labels.LabelArray{}
	m.Insert("10.1.1.0/24", lbls)
	m.Insert("10.2.0.0/20", lbls)
	m.Insert("10.3.3.3/32", lbls)
	m.Insert("10.4.4.0/26", lbls)
	m.Insert("10.5.0.0/16", lbls)
}

func (ds *PolicyTestSuite) TestToBPFData(c *C) {
	cidrPolicy := NewCIDRPolicy()

	populateMap(&cidrPolicy.Ingress)
	_, s4 := cidrPolicy.ToBPFData()
	exp := []int{32, 26, 24, 20, 16, 8, 0}
	c.Assert(s4, comparator.DeepEquals, exp)

	cidrPolicy = NewCIDRPolicy()
	// 8 and 0 represent the host/ cluster / world prefixes.
	populateMap(&cidrPolicy.Egress)
	_, s4 = cidrPolicy.ToBPFData()
	exp = []int{32, 26, 24, 20, 16, 8, 0}
	c.Assert(s4, comparator.DeepEquals, exp)
}

func (ds *PolicyTestSuite) TestGetDefaultPrefixLengths(c *C) {
	expected6 := []int{128, 64, 0}
	expected4 := []int{32, 8, 0}
	s6, s4 := GetDefaultPrefixLengths()

	c.Assert(s6, comparator.DeepEquals, expected6)
	c.Assert(s4, comparator.DeepEquals, expected4)
}
