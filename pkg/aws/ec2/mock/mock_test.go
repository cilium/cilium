// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/cidrset"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func TestMock(t *testing.T) {
	api := NewAPI([]*ipamTypes.Subnet{{ID: "s-1", AvailableAddresses: 100}}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}}, []*types.SecurityGroup{{ID: "sg-1"}}, []*ipamTypes.RouteTable{})
	require.NotNil(t, api)

	eniID1, _, err := api.CreateNetworkInterface(t.Context(), 8, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)

	eniID2, _, err := api.CreateNetworkInterface(t.Context(), 8, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)

	_, err = api.AttachNetworkInterface(t.Context(), 0, "i-1", eniID1)
	require.NoError(t, err)

	_, ok := api.enis["i-1"][eniID1]
	require.True(t, ok)

	_, err = api.AttachNetworkInterface(t.Context(), 1, "i-1", eniID2)
	require.NoError(t, err)

	_, ok = api.enis["i-1"][eniID1]
	require.True(t, ok)
	_, ok = api.enis["i-1"][eniID2]
	require.True(t, ok)

	// Attached ENIs cannot be deleted
	err = api.DeleteNetworkInterface(t.Context(), eniID1)
	require.Error(t, err)

	// Detach and delete ENI
	err = api.DetachNetworkInterface(t.Context(), "i-1", eniID1)
	require.NoError(t, err)
	err = api.DeleteNetworkInterface(t.Context(), eniID1)
	require.NoError(t, err)

	// ENIs cannot be deleted twice
	err = api.DeleteNetworkInterface(t.Context(), eniID1)
	require.Error(t, err)

	// Detach and delete ENI
	err = api.DetachNetworkInterface(t.Context(), "i-1", eniID2)
	require.NoError(t, err)
	err = api.DeleteNetworkInterface(t.Context(), eniID2)
	require.NoError(t, err)

	_, ok = api.enis["i-1"][eniID1]
	require.False(t, ok)
	_, ok = api.enis["i-1"][eniID2]
	require.False(t, ok)

	sg1 := &types.SecurityGroup{
		ID:    "sg1",
		VpcID: "vpc-1",
		Tags:  map[string]string{"k1": "v1"},
	}
	sg2 := &types.SecurityGroup{
		ID:    "sg2",
		VpcID: "vpc-1",
		Tags:  map[string]string{"k1": "v1"},
	}
	api.UpdateSecurityGroups([]*types.SecurityGroup{sg1, sg2})

	sgMap, err := api.GetSecurityGroups(t.Context())
	require.NoError(t, err)
	require.Equal(t, types.SecurityGroupMap{"sg1": sg1, "sg2": sg2}, sgMap)
}

func TestSetMockError(t *testing.T) {
	api := NewAPI([]*ipamTypes.Subnet{}, []*ipamTypes.VirtualNetwork{}, []*types.SecurityGroup{}, []*ipamTypes.RouteTable{})
	require.NotNil(t, api)

	mockError := errors.New("error")

	api.SetMockError(CreateNetworkInterface, mockError)
	_, _, err := api.CreateNetworkInterface(t.Context(), 8, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.Equal(t, mockError, err)

	api.SetMockError(AttachNetworkInterface, mockError)
	_, err = api.AttachNetworkInterface(t.Context(), 0, "i-1", "e-1")
	require.Equal(t, mockError, err)

	api.SetMockError(DeleteNetworkInterface, mockError)
	err = api.DeleteNetworkInterface(t.Context(), "e-1")
	require.Equal(t, mockError, err)

	api.SetMockError(AssignPrivateIpAddresses, mockError)
	_, err = api.AssignPrivateIpAddresses(t.Context(), "e-1", 10)
	require.Equal(t, mockError, err)

	api.SetMockError(UnassignPrivateIpAddresses, mockError)
	err = api.UnassignPrivateIpAddresses(t.Context(), "e-1", []string{"10.0.0.10", "10.0.0.11"})
	require.Equal(t, mockError, err)

	api.SetMockError(ModifyNetworkInterface, mockError)
	err = api.ModifyNetworkInterface(t.Context(), "e-1", "a-1", true)
	require.Equal(t, mockError, err)
}

func TestSetLimiter(t *testing.T) {
	api := NewAPI([]*ipamTypes.Subnet{{ID: "s-1", AvailableAddresses: 100}}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}}, []*types.SecurityGroup{{ID: "sg-1"}}, []*ipamTypes.RouteTable{})
	require.NotNil(t, api)

	api.SetLimiter(10.0, 2)
	_, _, err := api.CreateNetworkInterface(t.Context(), 8, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
}

func TestGetNextSubnet(t *testing.T) {
	_, cidrTest, _ := net.ParseCIDR("10.0.0.0/8")
	cidrSet, _ := cidrset.NewCIDRSet(cidrTest, 9)
	subnet, err := cidrSet.AllocateNext()
	require.NoError(t, err)
	require.Equal(t, "10.0.0.0/9", subnet.String())
	subnet, err = cidrSet.AllocateNext()
	require.NoError(t, err)
	require.Equal(t, "10.128.0.0/9", subnet.String())
}

func TestPrefixToIps(t *testing.T) {
	_, cidrTest, _ := net.ParseCIDR("10.128.0.0/9")
	cidrSet, _ := cidrset.NewCIDRSet(cidrTest, 28)
	subnet, err := cidrSet.AllocateNext()
	require.NoError(t, err)
	subnetStr := subnet.String()
	ips, _ := ip.PrefixToIps(subnetStr, 0)
	require.Equal(t, "10.128.0.0", ips[0])
	require.Equal(t, "10.128.0.15", ips[len(ips)-1])
}

func TestPrefixCeil(t *testing.T) {
	require.Equal(t, 1, ip.PrefixCeil(9, 16))
	require.Equal(t, 1, ip.PrefixCeil(16, 16))
	require.Equal(t, 2, ip.PrefixCeil(17, 16))
	require.Equal(t, 2, ip.PrefixCeil(31, 16))
	require.Equal(t, 2, ip.PrefixCeil(32, 16))
}

func TestGetRouteTables(t *testing.T) {
	routeTables := []*ipamTypes.RouteTable{
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
			VirtualNetworkID: "vpc-2",
			Subnets: map[string]struct{}{
				"subnet-3": {},
				"subnet-4": {},
			},
		},
	}

	api := NewAPI(
		[]*ipamTypes.Subnet{},
		[]*ipamTypes.VirtualNetwork{},
		[]*types.SecurityGroup{},
		routeTables,
	)

	tables, err := api.GetRouteTables(t.Context())
	require.NoError(t, err)
	require.Len(t, tables, 2)

	rt1, exists := tables["rt-1"]
	require.True(t, exists)
	require.Equal(t, "rt-1", rt1.ID)
	require.Equal(t, "vpc-1", rt1.VirtualNetworkID)
	require.Equal(t, map[string]struct{}{
		"subnet-1": {},
		"subnet-2": {},
	}, rt1.Subnets)

	rt2, exists := tables["rt-2"]
	require.True(t, exists)
	require.Equal(t, "rt-2", rt2.ID)
	require.Equal(t, "vpc-2", rt2.VirtualNetworkID)
	require.Equal(t, map[string]struct{}{
		"subnet-3": {},
		"subnet-4": {},
	}, rt2.Subnets)
}
