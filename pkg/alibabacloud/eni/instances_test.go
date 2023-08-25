// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"net"
	"testing"

	check "github.com/cilium/checkmate"

	apimock "github.com/cilium/cilium/pkg/alibabacloud/api/mock"
	eniTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type ENISuite struct{}

var _ = check.Suite(&ENISuite{})

var (
	_, subnet0, _ = net.ParseCIDR("1.1.0.0/24")
	_, subnet1, _ = net.ParseCIDR("1.1.1.0/24")

	vpcs = []*ipamTypes.VirtualNetwork{
		{
			ID:          "vpc-1",
			PrimaryCIDR: "1.1.0.0/16",
		},
	}

	subnets = []*ipamTypes.Subnet{
		{
			ID:                 "vsw-1",
			CIDR:               cidr.NewCIDR(subnet0),
			AvailableAddresses: 30,
			VirtualNetworkID:   "vpc-1",
			AvailabilityZone:   "cn-hangzhou-i",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		}, {
			ID:                 "vsw-2",
			CIDR:               cidr.NewCIDR(subnet1),
			AvailableAddresses: 40,
			VirtualNetworkID:   "vpc-1",
			AvailabilityZone:   "cn-hangzhou-h",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
	}

	securityGroups = []*types.SecurityGroup{
		{
			ID:    "sg-1",
			VPCID: "vpc-1",
			Tags:  map[string]string{"k1": "v1"},
		},
	}

	primaryENIs = map[string]apimock.ENIMap{
		"i-1": {
			"eni-1": {
				NetworkInterfaceID: "eni-1",
				PrimaryIPAddress:   "1.1.0.1",
				SecurityGroupIDs:   []string{"sg-1"},
				PrivateIPSets: []eniTypes.PrivateIPSet{
					{
						Primary:          true,
						PrivateIpAddress: "1.1.0.1",
					},
				},
				Type:       eniTypes.ENITypePrimary,
				InstanceID: "i-1",
				VSwitch:    eniTypes.VSwitch{VSwitchID: "vsw-1"},
				VPC:        eniTypes.VPC{VPCID: "vpc-1"},
				Tags:       map[string]string{},
			},
		},
		"i-2": {
			"eni-2": &eniTypes.ENI{
				NetworkInterfaceID: "eni-2",
				PrimaryIPAddress:   "1.1.1.1",
				SecurityGroupIDs:   []string{"sg-2"},
				PrivateIPSets: []eniTypes.PrivateIPSet{
					{
						Primary:          true,
						PrivateIpAddress: "1.1.1.1",
					},
				},
				Type:       eniTypes.ENITypePrimary,
				InstanceID: "i-2",
				VSwitch:    eniTypes.VSwitch{VSwitchID: "vsw-2"},
				VPC:        eniTypes.VPC{VPCID: "vpc-1"},
				Tags:       map[string]string{},
			},
		},
		"i-3": {
			"eni-3": &eniTypes.ENI{
				NetworkInterfaceID: "eni-3",
				PrimaryIPAddress:   "1.1.1.2",
				SecurityGroupIDs:   []string{"sg-2"},
				PrivateIPSets: []eniTypes.PrivateIPSet{
					{
						Primary:          true,
						PrivateIpAddress: "1.1.1.2",
					},
				},
				Type:       eniTypes.ENITypePrimary,
				InstanceID: "i-3",
				VSwitch:    eniTypes.VSwitch{VSwitchID: "vsw-2"},
				VPC:        eniTypes.VPC{VPCID: "vpc-1"},
				Tags:       map[string]string{},
			},
		},
	}
)
