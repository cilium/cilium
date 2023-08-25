// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"

	check "github.com/cilium/checkmate"

	ec2mock "github.com/cilium/cilium/pkg/aws/ec2/mock"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/checker"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

var (
	subnets = []*ipamTypes.Subnet{
		{
			ID:                 "subnet-1",
			AvailableAddresses: 10,
			VirtualNetworkID:   "vpc-1",
			AvailabilityZone:   "us-west-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:                 "subnet-2",
			AvailableAddresses: 20,
			VirtualNetworkID:   "vpc-2",
			AvailabilityZone:   "us-east-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
	}

	subnets2 = []*ipamTypes.Subnet{
		{
			ID:                 "subnet-1",
			AvailableAddresses: 10,
			VirtualNetworkID:   "vpc-1",
			AvailabilityZone:   "us-west-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:                 "subnet-2",
			AvailableAddresses: 20,
			VirtualNetworkID:   "vpc-2",
			AvailabilityZone:   "us-east-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:                 "subnet-3",
			AvailableAddresses: 0,
			VirtualNetworkID:   "vpc-1",
			AvailabilityZone:   "us-west-1",
			Tags: map[string]string{
				"tag2": "tag2",
			},
		},
	}

	vpcs = []*ipamTypes.VirtualNetwork{
		{
			ID:          "vpc-0",
			PrimaryCIDR: "1.1.0.0/16",
		},
		{
			ID:          "vpc-1",
			PrimaryCIDR: "2.2.0.0/16",
		},
	}

	securityGroups = []*types.SecurityGroup{
		{
			ID:    "sg-1",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k1": "v1"},
		},
		{
			ID:    "sg-2",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k2": "v2"},
		},
	}

	securityGroups2 = []*types.SecurityGroup{
		{
			ID:    "sg-1",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k1": "v1"},
		},
		{
			ID:    "sg-2",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k2": "v2"},
		},
		{
			ID:    "sg-3",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k3": "v3"},
		},
		{
			ID:    "sg-4",
			VpcID: "vpc-1",
			Tags:  map[string]string{"k3": "v3"},
		},
	}

	enis = map[string]ec2mock.ENIMap{
		"i-1": {
			"eni-1": {
				ID:             "eni-1",
				IP:             "1.1.1.1",
				Number:         0,
				SecurityGroups: []string{"sg1", "sg2"},
				Addresses:      []string{},
				Subnet:         eniTypes.AwsSubnet{ID: "subnet-1"},
				VPC:            eniTypes.AwsVPC{ID: "vpc-1"},
			},
		},
		"i-2": {
			"eni-3": &eniTypes.ENI{
				ID:             "eni-3",
				IP:             "3.3.3.3",
				Number:         0,
				SecurityGroups: []string{"sg3", "sg4"},
				Addresses:      []string{},
				Subnet:         eniTypes.AwsSubnet{ID: "subnet-2"},
				VPC:            eniTypes.AwsVPC{ID: "vpc-2"},
			},
		},
	}

	enis2 = map[string]ec2mock.ENIMap{
		"i-1": {
			"eni-1": {
				ID:             "eni-1",
				IP:             "1.1.1.1",
				Number:         0,
				SecurityGroups: []string{"sg1", "sg2"},
				Addresses:      []string{},
				Subnet:         eniTypes.AwsSubnet{ID: "subnet-1"},
				VPC:            eniTypes.AwsVPC{ID: "vpc-1"},
			},
			"eni-2": {
				ID:             "eni-2",
				IP:             "2.2.2.2",
				Number:         1,
				SecurityGroups: []string{"sg3", "sg4"},
				Addresses:      []string{},
				Subnet:         eniTypes.AwsSubnet{ID: "subnet-1"},
				VPC:            eniTypes.AwsVPC{ID: "vpc-1"},
			},
		},
		"i-2": {
			"eni-3": &eniTypes.ENI{
				ID:             "eni-3",
				IP:             "3.3.3.3",
				Number:         0,
				SecurityGroups: []string{"sg3", "sg4"},
				Addresses:      []string{},
				Subnet:         eniTypes.AwsSubnet{ID: "subnet-2"},
				VPC:            eniTypes.AwsVPC{ID: "vpc-2"},
			},
		},
	}
)

func iteration1(api *ec2mock.API, mngr *InstancesManager) {
	api.UpdateENIs(enis)
	mngr.Resync(context.TODO())
}

func iteration2(api *ec2mock.API, mngr *InstancesManager) {
	api.UpdateSubnets(subnets2)
	api.UpdateSecurityGroups(securityGroups2)
	api.UpdateENIs(enis2)
	mngr.Resync(context.TODO())
}

func (e *ENISuite) TestGetSubnet(c *check.C) {
	api := ec2mock.NewAPI(subnets, vpcs, securityGroups)
	c.Assert(api, check.Not(check.IsNil))

	mngr := NewInstancesManager(api)
	c.Assert(mngr, check.Not(check.IsNil))

	c.Assert(mngr.GetSubnet("subnet-1"), check.IsNil)
	c.Assert(mngr.GetSubnet("subnet-2"), check.IsNil)
	c.Assert(mngr.GetSubnet("subnet-3"), check.IsNil)

	iteration1(api, mngr)

	subnet1 := mngr.GetSubnet("subnet-1")
	c.Assert(subnet1, check.Not(check.IsNil))
	c.Assert(subnet1.ID, check.Equals, "subnet-1")

	subnet2 := mngr.GetSubnet("subnet-2")
	c.Assert(subnet2, check.Not(check.IsNil))
	c.Assert(subnet2.ID, check.Equals, "subnet-2")

	c.Assert(mngr.GetSubnet("subnet-3"), check.IsNil)

	iteration2(api, mngr)

	subnet1 = mngr.GetSubnet("subnet-1")
	c.Assert(subnet1, check.Not(check.IsNil))
	c.Assert(subnet1.ID, check.Equals, "subnet-1")

	subnet2 = mngr.GetSubnet("subnet-2")
	c.Assert(subnet2, check.Not(check.IsNil))
	c.Assert(subnet2.ID, check.Equals, "subnet-2")

	subnet3 := mngr.GetSubnet("subnet-3")
	c.Assert(subnet3, check.Not(check.IsNil))
	c.Assert(subnet3.ID, check.Equals, "subnet-3")
}

func (e *ENISuite) TestFindSubnetByIDs(c *check.C) {
	api := ec2mock.NewAPI(subnets2, vpcs, securityGroups)
	c.Assert(api, check.Not(check.IsNil))

	mngr := NewInstancesManager(api)
	c.Assert(mngr, check.Not(check.IsNil))

	iteration1(api, mngr)
	iteration2(api, mngr)

	// exact match subnet-1
	s := mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-1"})
	c.Assert(s.ID, check.Equals, "subnet-1")

	// exact match subnet-2
	s = mngr.FindSubnetByIDs("vpc-2", "us-east-1", []string{"subnet-2"})
	c.Assert(s.ID, check.Equals, "subnet-2")

	// exact match subnet-3
	s = mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-3"})
	c.Assert(s.ID, check.Equals, "subnet-3")

	// empty list shall return nil
	c.Assert(mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{}), check.IsNil)

	// all subnet match, subnet-1 has more addresses
	s = mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-1", "subnet-3"})
	c.Assert(s.ID, check.Equals, "subnet-1")

	// invalid vpc, no match
	c.Assert(mngr.FindSubnetByIDs("vpc-unknown", "us-west-1", []string{"subnet-1"}), check.IsNil)

	// invalid AZ, no match
	c.Assert(mngr.FindSubnetByIDs("vpc-1", "us-west-unknown", []string{"subnet-1"}), check.IsNil)

	// invalid ids, no match
	c.Assert(mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-unknown"}), check.IsNil)
}

func (e *ENISuite) TestFindSubnetByTags(c *check.C) {
	api := ec2mock.NewAPI(subnets, vpcs, securityGroups)
	c.Assert(api, check.Not(check.IsNil))

	mngr := NewInstancesManager(api)
	c.Assert(mngr, check.Not(check.IsNil))

	iteration1(api, mngr)
	iteration2(api, mngr)

	// exact match subnet-1
	s := mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{"tag1": "tag1"})
	c.Assert(s.ID, check.Equals, "subnet-1")

	// exact match subnet-2
	s = mngr.FindSubnetByTags("vpc-2", "us-east-1", ipamTypes.Tags{"tag1": "tag1"})
	c.Assert(s.ID, check.Equals, "subnet-2")

	// exact match subnet-3
	s = mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{"tag2": "tag2"})
	c.Assert(s.ID, check.Equals, "subnet-3")

	// both subnet-1 and subnet-3 match, subnet-1 has more addresses
	s = mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{})
	c.Assert(s.ID, check.Equals, "subnet-1")

	// invalid vpc, no match
	c.Assert(mngr.FindSubnetByTags("vpc-unknown", "us-west-1", ipamTypes.Tags{"tag1": "tag1"}), check.IsNil)

	// invalid AZ, no match
	c.Assert(mngr.FindSubnetByTags("vpc-1", "us-west-unknown", ipamTypes.Tags{"tag1": "tag1"}), check.IsNil)

	// invalid tags, no match
	c.Assert(mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{"tag1": "unknown value"}), check.IsNil)
}

func (e *ENISuite) TestGetSecurityGroupByTags(c *check.C) {
	api := ec2mock.NewAPI(subnets, vpcs, securityGroups)
	c.Assert(api, check.Not(check.IsNil))

	mngr := NewInstancesManager(api)
	c.Assert(mngr, check.Not(check.IsNil))

	sgGroups := mngr.FindSecurityGroupByTags("vpc-1", map[string]string{
		"k1": "v1",
	})
	c.Assert(sgGroups, check.HasLen, 0)

	iteration1(api, mngr)
	reqTags := ipamTypes.Tags{
		"k1": "v1",
	}
	sgGroups = mngr.FindSecurityGroupByTags("vpc-1", reqTags)
	c.Assert(sgGroups, check.HasLen, 1)
	c.Assert(sgGroups[0].Tags, checker.DeepEquals, reqTags)

	iteration2(api, mngr)
	reqTags = ipamTypes.Tags{
		"k2": "v2",
	}
	sgGroups = mngr.FindSecurityGroupByTags("vpc-1", reqTags)
	c.Assert(sgGroups, check.HasLen, 1)
	c.Assert(sgGroups[0].Tags, checker.DeepEquals, reqTags)

	// iteration 3
	mngr.Resync(context.TODO())
	reqTags = ipamTypes.Tags{
		"k3": "v3",
	}
	sgGroups = mngr.FindSecurityGroupByTags("vpc-1", reqTags)
	c.Assert(sgGroups, check.HasLen, 2)
	c.Assert(sgGroups[0].Tags, checker.DeepEquals, reqTags)
	c.Assert(sgGroups[1].Tags, checker.DeepEquals, reqTags)
}
