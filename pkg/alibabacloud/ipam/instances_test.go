// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net/netip"

	apimock "github.com/cilium/cilium/pkg/alibabacloud/api/mock"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

var (
	subnet0 = netip.MustParsePrefix("1.1.0.0/24")
	subnet1 = netip.MustParsePrefix("1.1.1.0/24")

	vpcs = []*ipamTypes.VirtualNetwork{
		{
			ID:          "vpc-1",
			PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("1.1.0.0/16")),
		},
	}

	subnets = []*ipamTypes.Subnet{
		{
			ID:                 "vsw-1",
			CIDR:               subnet0,
			AvailableAddresses: 30,
			VirtualNetworkID:   "vpc-1",
			AvailabilityZone:   "cn-hangzhou-i",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		}, {
			ID:                 "vsw-2",
			CIDR:               subnet1,
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
				PrimaryIPAddress:   iputil.AddrFrom(netip.MustParseAddr("1.1.0.1")),
				SecurityGroupIDs:   []string{"sg-1"},
				PrivateIPSets: []types.PrivateIPSet{
					{
						Primary:          true,
						PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("1.1.0.1")),
					},
				},
				Type:       types.ENITypePrimary,
				InstanceID: "i-1",
				VSwitch:    types.VSwitch{VSwitchID: "vsw-1"},
				VPC:        types.VPC{VPCID: "vpc-1"},
				Tags:       map[string]string{},
			},
		},
		"i-2": {
			"eni-2": &types.ENI{
				NetworkInterfaceID: "eni-2",
				PrimaryIPAddress:   iputil.AddrFrom(netip.MustParseAddr("1.1.1.1")),
				SecurityGroupIDs:   []string{"sg-2"},
				PrivateIPSets: []types.PrivateIPSet{
					{
						Primary:          true,
						PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("1.1.1.1")),
					},
				},
				Type:       types.ENITypePrimary,
				InstanceID: "i-2",
				VSwitch:    types.VSwitch{VSwitchID: "vsw-2"},
				VPC:        types.VPC{VPCID: "vpc-1"},
				Tags:       map[string]string{},
			},
		},
		"i-3": {
			"eni-3": &types.ENI{
				NetworkInterfaceID: "eni-3",
				PrimaryIPAddress:   iputil.AddrFrom(netip.MustParseAddr("1.1.1.2")),
				SecurityGroupIDs:   []string{"sg-2"},
				PrivateIPSets: []types.PrivateIPSet{
					{
						Primary:          true,
						PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("1.1.1.2")),
					},
				},
				Type:       types.ENITypePrimary,
				InstanceID: "i-3",
				VSwitch:    types.VSwitch{VSwitchID: "vsw-2"},
				VPC:        types.VPC{VPCID: "vpc-1"},
				Tags:       map[string]string{},
			},
		},
	}
)
