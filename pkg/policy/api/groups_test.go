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

package api

import (
	"fmt"
	"net"

	. "gopkg.in/check.v1"
)

func GetToGroupsRule() ToGroups {
	return ToGroups{
		Aws: &AWSGroups{
			Labels: map[string]string{
				"test": "a",
			},
			SecurityGroupsIds: []string{
				"a", "b", "c",
			},
			SecurityGroupsNames: []string{
				"a", "b", "c",
			},
		},
	}
}
func GetCallBackWithRule(ips ...string) (ProviderIntegration, []CIDRRule) {
	netIPs := []net.IP{}
	cidrRule := []CIDRRule{}
	for _, ip := range ips {
		netIPs = append(netIPs, net.ParseIP(ip))
		rule := CIDRRule{
			Cidr:        CIDR(ip + "/32"),
			ExceptCIDRs: []CIDR{},
			Generated:   true}
		cidrRule = append(cidrRule, rule)
	}

	cb := func(group *ToGroups) ([]net.IP, error) {
		return netIPs, nil
	}

	return cb, cidrRule

}

func (s *PolicyAPITestSuite) TestGetCIDRSetWithValidValue(c *C) {
	cb, cidrRule := GetCallBackWithRule("192.168.1.1")
	RegisterToGroupsProvider(AWSPROVIDER, cb)

	group := GetToGroupsRule()
	cidr, err := group.GetCidrSet()
	c.Assert(cidr, DeepEquals, cidrRule)
	c.Assert(err, IsNil)
}

func (s *PolicyAPITestSuite) TestGetCIDRSetWithMultipleSorted(c *C) {
	cb, cidrRule := GetCallBackWithRule("192.168.1.1", "192.168.10.10")
	RegisterToGroupsProvider(AWSPROVIDER, cb)

	group := GetToGroupsRule()
	cidr, err := group.GetCidrSet()
	c.Assert(cidr, DeepEquals, cidrRule)
	c.Assert(err, IsNil)
}

func (s *PolicyAPITestSuite) TestGetCIDRSetWithUniqueCIDRRule(c *C) {
	cb, _ := GetCallBackWithRule("192.168.1.1", "192.168.10.10", "192.168.1.1")
	RegisterToGroupsProvider(AWSPROVIDER, cb)

	cidrRule := []CIDRRule{
		CIDRRule{Cidr: "192.168.1.1/32", ExceptCIDRs: []CIDR{}, Generated: true},
		CIDRRule{Cidr: "192.168.10.10/32", ExceptCIDRs: []CIDR{}, Generated: true}}

	group := GetToGroupsRule()
	cidr, err := group.GetCidrSet()
	c.Assert(cidr, DeepEquals, cidrRule)
	c.Assert(err, IsNil)
}

func (s *PolicyAPITestSuite) TestGetCIDRSetWithError(c *C) {

	cb := func(group *ToGroups) ([]net.IP, error) {
		return []net.IP{}, fmt.Errorf("Invalid credentials")
	}
	RegisterToGroupsProvider(AWSPROVIDER, cb)
	group := GetToGroupsRule()
	cidr, err := group.GetCidrSet()
	c.Assert(cidr, DeepEquals, []CIDRRule{})
	c.Assert(err, NotNil)
}

func (s *PolicyAPITestSuite) TestWithoutProviderRegister(c *C) {
	providers.Delete(AWSPROVIDER)
	group := GetToGroupsRule()
	cidr, err := group.GetCidrSet()
	c.Assert(cidr, DeepEquals, []CIDRRule{})
	c.Assert(err, NotNil)
}
