// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package policy

import (
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"
)

func (ds *PolicyTestSuite) SetUpTest(c *C) {
	v6node := cidr.MustParseCIDR("2001:DB8::/96")
	v4node := cidr.MustParseCIDR("192.0.2.3/24")
	node.SetIPv6NodeRange(v6node)
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
	exp := []int{32, 26, 24, 20, 16, 0}
	c.Assert(s4, checker.DeepEquals, exp)

	cidrPolicy = NewCIDRPolicy()
	// 32 represent the host and 0 the world prefixes.
	populateMap(&cidrPolicy.Egress)
	_, s4 = cidrPolicy.ToBPFData()
	exp = []int{32, 26, 24, 20, 16, 0}
	c.Assert(s4, checker.DeepEquals, exp)
}

func (ds *PolicyTestSuite) TestGetDefaultPrefixLengths(c *C) {
	expected6 := []int{128, 0}
	expected4 := []int{32, 0}
	s6, s4 := GetDefaultPrefixLengths()

	c.Assert(s6, checker.DeepEquals, expected6)
	c.Assert(s4, checker.DeepEquals, expected4)
}
