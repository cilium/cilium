// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package api

import (
	"context"
	"fmt"
	"net"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
)

func GetToGroupsRule() ToGroups {
	return ToGroups{
		AWS: &AWSGroup{
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
func GetCallBackWithRule(ips ...string) GroupProviderFunc {
	netIPs := []net.IP{}
	for _, ip := range ips {
		netIPs = append(netIPs, net.ParseIP(ip))
	}

	cb := func(ctx context.Context, group *ToGroups) ([]net.IP, error) {
		return netIPs, nil
	}

	return cb
}

func (s *PolicyAPITestSuite) TestGetCIDRSetWithValidValue(c *C) {
	cb := GetCallBackWithRule("192.168.1.1")
	RegisterToGroupsProvider(AWSProvider, cb)

	expectedCidrRule := []CIDRRule{
		{Cidr: "192.168.1.1/32", ExceptCIDRs: []CIDR{}, Generated: true}}
	group := GetToGroupsRule()
	cidr, err := group.GetCidrSet(context.TODO())
	c.Assert(cidr, checker.DeepEquals, expectedCidrRule)
	c.Assert(err, IsNil)
}

func (s *PolicyAPITestSuite) TestGetCIDRSetWithMultipleSorted(c *C) {
	cb := GetCallBackWithRule("192.168.1.1", "192.168.10.10", "192.168.10.3")
	RegisterToGroupsProvider(AWSProvider, cb)
	expectedCidrRule := []CIDRRule{
		{Cidr: "192.168.1.1/32", ExceptCIDRs: []CIDR{}, Generated: true},
		{Cidr: "192.168.10.3/32", ExceptCIDRs: []CIDR{}, Generated: true},
		{Cidr: "192.168.10.10/32", ExceptCIDRs: []CIDR{}, Generated: true}}
	group := GetToGroupsRule()
	cidr, err := group.GetCidrSet(context.TODO())
	c.Assert(cidr, checker.DeepEquals, expectedCidrRule)
	c.Assert(err, IsNil)
}

func (s *PolicyAPITestSuite) TestGetCIDRSetWithUniqueCIDRRule(c *C) {
	cb := GetCallBackWithRule("192.168.1.1", "192.168.10.10", "192.168.1.1")
	RegisterToGroupsProvider(AWSProvider, cb)

	cidrRule := []CIDRRule{
		{Cidr: "192.168.1.1/32", ExceptCIDRs: []CIDR{}, Generated: true},
		{Cidr: "192.168.10.10/32", ExceptCIDRs: []CIDR{}, Generated: true}}

	group := GetToGroupsRule()
	cidr, err := group.GetCidrSet(context.TODO())
	c.Assert(cidr, checker.DeepEquals, cidrRule)
	c.Assert(err, IsNil)
}

func (s *PolicyAPITestSuite) TestGetCIDRSetWithError(c *C) {

	cb := func(ctx context.Context, group *ToGroups) ([]net.IP, error) {
		return []net.IP{}, fmt.Errorf("Invalid credentials")
	}
	RegisterToGroupsProvider(AWSProvider, cb)
	group := GetToGroupsRule()
	cidr, err := group.GetCidrSet(context.TODO())
	c.Assert(cidr, IsNil)
	c.Assert(err, NotNil)

}

func (s *PolicyAPITestSuite) TestWithoutProviderRegister(c *C) {
	providers.Delete(AWSProvider)
	group := GetToGroupsRule()
	cidr, err := group.GetCidrSet(context.TODO())
	c.Assert(cidr, IsNil)
	c.Assert(err, NotNil)
}
