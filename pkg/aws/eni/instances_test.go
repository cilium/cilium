// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	ec2mock "github.com/cilium/cilium/pkg/aws/ec2/mock"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/types"
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
	routeTables = []*ipamTypes.RouteTable{
		{
			ID:               "rt-1",
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-1": {},
				"subnet-2": {},
			},
		},
		{
			ID:               "rt-2",
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-3": {},
				"subnet-4": {},
			},
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

func iteration1(t *testing.T, api *ec2mock.API, mngr *InstancesManager) {
	api.UpdateENIs(enis)
	mngr.Resync(t.Context())
}

func iteration2(t *testing.T, api *ec2mock.API, mngr *InstancesManager) {
	api.UpdateSubnets(subnets2)
	api.UpdateSecurityGroups(securityGroups2)
	api.UpdateENIs(enis2)
	mngr.Resync(t.Context())
}

func TestGetSubnet(t *testing.T) {
	api := ec2mock.NewAPI(subnets, vpcs, securityGroups, routeTables)
	require.NotNil(t, api)

	mngr, err := NewInstancesManager(hivetest.Logger(t), api)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	require.Nil(t, mngr.GetSubnet("subnet-1"))
	require.Nil(t, mngr.GetSubnet("subnet-2"))
	require.Nil(t, mngr.GetSubnet("subnet-3"))

	iteration1(t, api, mngr)

	subnet1 := mngr.GetSubnet("subnet-1")
	require.NotNil(t, subnet1)
	require.Equal(t, "subnet-1", subnet1.ID)

	subnet2 := mngr.GetSubnet("subnet-2")
	require.NotNil(t, subnet2)
	require.Equal(t, "subnet-2", subnet2.ID)

	require.Nil(t, mngr.GetSubnet("subnet-3"))

	iteration2(t, api, mngr)

	subnet1 = mngr.GetSubnet("subnet-1")
	require.NotNil(t, subnet1)
	require.Equal(t, "subnet-1", subnet1.ID)

	subnet2 = mngr.GetSubnet("subnet-2")
	require.NotNil(t, subnet2)
	require.Equal(t, "subnet-2", subnet2.ID)

	subnet3 := mngr.GetSubnet("subnet-3")
	require.NotNil(t, subnet3)
	require.Equal(t, "subnet-3", subnet3.ID)
}

func TestFindSubnetByIDs(t *testing.T) {
	api := ec2mock.NewAPI(subnets2, vpcs, securityGroups, routeTables)
	require.NotNil(t, api)

	mngr, err := NewInstancesManager(hivetest.Logger(t), api)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	iteration1(t, api, mngr)
	iteration2(t, api, mngr)

	// exact match subnet-1
	s := mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-1"})
	require.Equal(t, "subnet-1", s.ID)

	// exact match subnet-2
	s = mngr.FindSubnetByIDs("vpc-2", "us-east-1", []string{"subnet-2"})
	require.Equal(t, "subnet-2", s.ID)

	// exact match subnet-3
	s = mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-3"})
	require.Equal(t, "subnet-3", s.ID)

	// empty list shall return nil
	require.Nil(t, mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{}))

	// all subnet match, subnet-1 has more addresses
	s = mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-1", "subnet-3"})
	require.Equal(t, "subnet-1", s.ID)

	// invalid vpc, no match
	require.Nil(t, mngr.FindSubnetByIDs("vpc-unknown", "us-west-1", []string{"subnet-1"}))

	// invalid AZ, no match
	require.Nil(t, mngr.FindSubnetByIDs("vpc-1", "us-west-unknown", []string{"subnet-1"}))

	// invalid ids, no match
	require.Nil(t, mngr.FindSubnetByIDs("vpc-1", "us-west-1", []string{"subnet-unknown"}))
}

func TestFindSubnetByTags(t *testing.T) {
	api := ec2mock.NewAPI(subnets, vpcs, securityGroups, routeTables)
	require.NotNil(t, api)

	mngr, err := NewInstancesManager(hivetest.Logger(t), api)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	iteration1(t, api, mngr)
	iteration2(t, api, mngr)

	// exact match subnet-1
	s := mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{"tag1": "tag1"})
	require.Equal(t, "subnet-1", s.ID)

	// exact match subnet-2
	s = mngr.FindSubnetByTags("vpc-2", "us-east-1", ipamTypes.Tags{"tag1": "tag1"})
	require.Equal(t, "subnet-2", s.ID)

	// exact match subnet-3
	s = mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{"tag2": "tag2"})
	require.Equal(t, "subnet-3", s.ID)

	// both subnet-1 and subnet-3 match, subnet-1 has more addresses
	s = mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{})
	require.Equal(t, "subnet-1", s.ID)

	// invalid vpc, no match
	require.Nil(t, mngr.FindSubnetByTags("vpc-unknown", "us-west-1", ipamTypes.Tags{"tag1": "tag1"}))

	// invalid AZ, no match
	require.Nil(t, mngr.FindSubnetByTags("vpc-1", "us-west-unknown", ipamTypes.Tags{"tag1": "tag1"}))

	// invalid tags, no match
	require.Nil(t, mngr.FindSubnetByTags("vpc-1", "us-west-1", ipamTypes.Tags{"tag1": "tag1", "tag2": "tag2"}))
}

func TestGetSecurityGroupByTags(t *testing.T) {
	api := ec2mock.NewAPI(subnets, vpcs, securityGroups, routeTables)
	require.NotNil(t, api)

	mngr, err := NewInstancesManager(hivetest.Logger(t), api)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	sgGroups := mngr.FindSecurityGroupByTags("vpc-1", map[string]string{
		"k1": "v1",
	})
	require.Empty(t, sgGroups)

	iteration1(t, api, mngr)
	reqTags := ipamTypes.Tags{
		"k1": "v1",
	}
	sgGroups = mngr.FindSecurityGroupByTags("vpc-1", reqTags)
	require.Len(t, sgGroups, 1)
	require.Equal(t, reqTags, sgGroups[0].Tags)

	iteration2(t, api, mngr)
	reqTags = ipamTypes.Tags{
		"k2": "v2",
	}
	sgGroups = mngr.FindSecurityGroupByTags("vpc-1", reqTags)
	require.Len(t, sgGroups, 1)
	require.Equal(t, reqTags, sgGroups[0].Tags)

	// iteration 3
	mngr.Resync(t.Context())
	reqTags = ipamTypes.Tags{
		"k3": "v3",
	}
	sgGroups = mngr.FindSecurityGroupByTags("vpc-1", reqTags)
	require.Len(t, sgGroups, 2)
	require.Equal(t, reqTags, sgGroups[0].Tags)
	require.Equal(t, reqTags, sgGroups[1].Tags)
}
