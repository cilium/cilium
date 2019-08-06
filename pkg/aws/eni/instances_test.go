// Copyright 2019 Authors of Cilium
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

package eni

import (
	metricsmock "github.com/cilium/cilium/pkg/aws/eni/metrics/mock"
	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	"gopkg.in/check.v1"
)

type instancesApiMock struct {
	instancesIteration int
	subnetsIteration   int
}

func (i *instancesApiMock) GetInstances(vpcs types.VpcMap, subnets types.SubnetMap) (m types.InstanceMap, err error) {
	i.instancesIteration++

	m = types.InstanceMap{}

	m.Add("i-1", &v2.ENI{
		ID:             "eni-1",
		IP:             "1.1.1.1",
		Number:         0,
		SecurityGroups: []string{"sg1", "sg2"},
		Addresses:      []string{},
		Subnet:         v2.AwsSubnet{ID: "subnet-1"},
		VPC:            v2.AwsVPC{ID: "vpc-1"},
	})

	if i.instancesIteration > 1 {
		m.Add("i-1", &v2.ENI{
			ID:             "eni-2",
			IP:             "2.2.2.2",
			Number:         1,
			SecurityGroups: []string{"sg3", "sg4"},
			Addresses:      []string{},
			Subnet:         v2.AwsSubnet{ID: "subnet-1"},
			VPC:            v2.AwsVPC{ID: "vpc-1"},
		})
	}

	m.Add("i-2", &v2.ENI{
		ID:             "eni-3",
		IP:             "3.3.3.3",
		Number:         0,
		SecurityGroups: []string{"sg3", "sg4"},
		Addresses:      []string{},
		Subnet:         v2.AwsSubnet{ID: "subnet-2"},
		VPC:            v2.AwsVPC{ID: "vpc-2"},
	})

	return
}

func (i *instancesApiMock) GetVpcs() (v types.VpcMap, err error) {
	v = types.VpcMap{}

	v["vpc-0"] = &types.Vpc{
		ID:          "vpc-0",
		PrimaryCIDR: "1.1.0.0/16",
	}

	v["vpc-1"] = &types.Vpc{
		ID:          "vpc-1",
		PrimaryCIDR: "2.2.0.0/16",
	}

	return
}

func (i *instancesApiMock) GetSubnets() (s types.SubnetMap, err error) {
	i.subnetsIteration++

	s = types.SubnetMap{}

	s["subnet-1"] = &types.Subnet{
		ID:                 "subnet-1",
		CIDR:               "",
		AvailableAddresses: 10,
		VpcID:              "vpc-1",
		AvailabilityZone:   "us-west-1",
		Tags: map[string]string{
			"tag1": "tag1",
		},
	}

	s["subnet-2"] = &types.Subnet{
		ID:                 "subnet-2",
		CIDR:               "",
		AvailableAddresses: 20,
		VpcID:              "vpc-2",
		AvailabilityZone:   "us-east-1",
		Tags: map[string]string{
			"tag1": "tag1",
		},
	}

	if i.subnetsIteration > 1 {
		s["subnet-3"] = &types.Subnet{
			ID:                 "subnet-3",
			CIDR:               "",
			AvailableAddresses: 0,
			VpcID:              "vpc-1",
			AvailabilityZone:   "us-west-1",
			Tags: map[string]string{
				"tag2": "tag2",
			},
		}
	}

	return
}

func (e *ENISuite) TestGetSubnet(c *check.C) {
	mngr := NewInstancesManager(&instancesApiMock{}, metricsmock.NewMockMetrics())
	c.Assert(mngr, check.Not(check.IsNil))

	c.Assert(mngr.GetSubnet("subnet-1"), check.IsNil)
	c.Assert(mngr.GetSubnet("subnet-2"), check.IsNil)
	c.Assert(mngr.GetSubnet("subnet-3"), check.IsNil)

	// iteration 1
	mngr.Resync()

	subnet1 := mngr.GetSubnet("subnet-1")
	c.Assert(subnet1, check.Not(check.IsNil))
	c.Assert(subnet1.ID, check.Equals, "subnet-1")

	subnet2 := mngr.GetSubnet("subnet-2")
	c.Assert(subnet2, check.Not(check.IsNil))
	c.Assert(subnet2.ID, check.Equals, "subnet-2")

	c.Assert(mngr.GetSubnet("subnet-3"), check.IsNil)

	// iteration 2
	mngr.Resync()

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

func (e *ENISuite) TestFindSubnetByTags(c *check.C) {
	mngr := NewInstancesManager(&instancesApiMock{}, metricsmock.NewMockMetrics())
	c.Assert(mngr, check.Not(check.IsNil))

	// iteration 1 + 2
	mngr.Resync()
	mngr.Resync()

	// exact match subnet-1
	s := mngr.FindSubnetByTags("vpc-1", "us-west-1", types.Tags{"tag1": "tag1"})
	c.Assert(s.ID, check.Equals, "subnet-1")

	// exact match subnet-2
	s = mngr.FindSubnetByTags("vpc-2", "us-east-1", types.Tags{"tag1": "tag1"})
	c.Assert(s.ID, check.Equals, "subnet-2")

	// exact match subnet-3
	s = mngr.FindSubnetByTags("vpc-1", "us-west-1", types.Tags{"tag2": "tag2"})
	c.Assert(s.ID, check.Equals, "subnet-3")

	// both subnet-1 and subnet-3 match, subnet-1 has more addresses
	s = mngr.FindSubnetByTags("vpc-1", "us-west-1", types.Tags{})
	c.Assert(s.ID, check.Equals, "subnet-1")

	// invalid vpc, no match
	c.Assert(mngr.FindSubnetByTags("vpc-unknown", "us-west-1", types.Tags{"tag1": "tag1"}), check.IsNil)

	// invalid AZ, no match
	c.Assert(mngr.FindSubnetByTags("vpc-1", "us-west-unknown", types.Tags{"tag1": "tag1"}), check.IsNil)

	// invalid tags, no match
	c.Assert(mngr.FindSubnetByTags("vpc-1", "us-west-1", types.Tags{"tag1": "unknown value"}), check.IsNil)
}

func (e *ENISuite) TestGetENIs(c *check.C) {
	mngr := NewInstancesManager(&instancesApiMock{}, metricsmock.NewMockMetrics())
	c.Assert(mngr, check.Not(check.IsNil))

	// iteration 1
	mngr.Resync()
	c.Assert(len(mngr.GetENIs("i-1")), check.Equals, 1)
	c.Assert(len(mngr.GetENIs("i-2")), check.Equals, 1)
	c.Assert(len(mngr.GetENIs("i-unknown")), check.Equals, 0)

	// iteration 2
	mngr.Resync()
	c.Assert(len(mngr.GetENIs("i-1")), check.Equals, 2)
	c.Assert(len(mngr.GetENIs("i-2")), check.Equals, 1)
	c.Assert(len(mngr.GetENIs("i-unknown")), check.Equals, 0)
}

func (e *ENISuite) TestGetENI(c *check.C) {
	mngr := NewInstancesManager(&instancesApiMock{}, metricsmock.NewMockMetrics())
	c.Assert(mngr, check.Not(check.IsNil))

	// iteration 1
	mngr.Resync()
	c.Assert(mngr.GetENI("i-1", 0), check.Not(check.IsNil))
	c.Assert(mngr.GetENI("i-1", 1), check.IsNil)
	c.Assert(mngr.GetENI("i-2", 0), check.Not(check.IsNil))

	// iteration 2
	mngr.Resync()
	c.Assert(mngr.GetENI("i-1", 0), check.Not(check.IsNil))
	c.Assert(mngr.GetENI("i-1", 1), check.Not(check.IsNil))
	c.Assert(mngr.GetENI("i-2", 0), check.Not(check.IsNil))
}
