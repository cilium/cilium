// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func TestMock(t *testing.T) {
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr.MustParseCIDR("10.0.0.0/16"), AvailableAddresses: 65534}
	api := NewAPI([]*ipamTypes.Subnet{subnet})
	require.NotNil(t, api)

	instances, err := api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
	require.Equal(t, 0, instances.NumInstances())

	specificSubnets, err := api.GetNodesSubnets(context.Background(), []string{"s-1"})
	require.NoError(t, err)
	require.Equal(t, 1, len(specificSubnets))
	require.Equal(t, subnet, specificSubnets["s-1"])

	ifaceID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11"
	instances = ipamTypes.NewInstanceMap()
	resource := &types.AzureInterface{Name: "eth0"}
	resource.SetID(ifaceID)
	instances.Update("vm1", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})
	api.UpdateInstances(instances)
	instances, err = api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
	require.Equal(t, 1, instances.NumInstances())
	instances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.InterfaceRevision) error {
		require.Equal(t, "vm1", instanceID)
		require.Equal(t, ifaceID, interfaceID)
		return nil
	})

	err = api.AssignPrivateIpAddressesVMSS(context.Background(), "vm1", "vmss1", "s-1", "eth0", 2)
	require.NoError(t, err)
	instances, err = api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
	require.Equal(t, 1, instances.NumInstances())
	instances.ForeachInterface("", func(instanceID, interfaceID string, revision ipamTypes.InterfaceRevision) error {
		require.Equal(t, "vm1", instanceID)
		require.Equal(t, ifaceID, interfaceID)

		iface, ok := revision.Resource.(*types.AzureInterface)
		require.True(t, ok)
		require.Equal(t, 2, len(iface.Addresses))
		return nil
	})

	vmIfaceID := "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Network/networkInterfaces/vm22-if"
	vmInstances := ipamTypes.NewInstanceMap()
	resource = &types.AzureInterface{Name: "eth0"}
	resource.SetID(vmIfaceID)
	vmInstances.Update("vm2", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})
	require.NoError(t, err)
	require.Equal(t, 1, vmInstances.NumInstances())
	vmInstances.ForeachInterface("", func(instanceID, interfaceID string, iface ipamTypes.InterfaceRevision) error {
		require.Equal(t, "vm2", instanceID)
		require.Equal(t, vmIfaceID, interfaceID)
		return nil
	})

}

func TestSetMockError(t *testing.T) {
	api := NewAPI([]*ipamTypes.Subnet{})
	require.NotNil(t, api)

	mockError := errors.New("error")

	api.SetMockError(GetInstances, mockError)
	_, err := api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	require.ErrorIs(t, err, mockError)

	api.SetMockError(AssignPrivateIpAddressesVMSS, mockError)
	err = api.AssignPrivateIpAddressesVMSS(context.Background(), "vmss1", "i-1", "s-1", "eth0", 0)
	require.ErrorIs(t, err, mockError)

	api.SetMockError(GetNodesSubnets, mockError)
	_, err = api.GetNodesSubnets(context.Background(), []string{"s-1"})
	require.ErrorIs(t, err, mockError)
}

func TestSetLimiter(t *testing.T) {
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr.MustParseCIDR("10.0.0.0/16"), AvailableAddresses: 100}
	api := NewAPI([]*ipamTypes.Subnet{subnet})
	require.NotNil(t, api)

	api.SetLimiter(10.0, 2)
	_, err := api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
}

func TestGetNodesSubnets(t *testing.T) {
	subnet1 := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr.MustParseCIDR("10.0.0.0/16"), AvailableAddresses: 65534}
	subnet2 := &ipamTypes.Subnet{ID: "s-2", CIDR: cidr.MustParseCIDR("10.1.0.0/16"), AvailableAddresses: 32768}
	subnet3 := &ipamTypes.Subnet{ID: "s-3", CIDR: cidr.MustParseCIDR("10.2.0.0/16"), AvailableAddresses: 16384}

	api := NewAPI([]*ipamTypes.Subnet{subnet1, subnet2, subnet3})
	require.NotNil(t, api)

	// Test getting node subnets
	subnets, err := api.GetNodesSubnets(context.Background(), []string{"s-1", "s-3"})
	require.NoError(t, err)
	require.Equal(t, 2, len(subnets))
	require.Equal(t, subnet1.ID, subnets["s-1"].ID)
	require.Equal(t, subnet1.CIDR, subnets["s-1"].CIDR)
	require.Equal(t, subnet3.ID, subnets["s-3"].ID)
	require.Equal(t, subnet3.CIDR, subnets["s-3"].CIDR)

	// Verify s-2 is not included
	_, exists := subnets["s-2"]
	require.False(t, exists)

	// Test getting non-existent subnet
	subnets, err = api.GetNodesSubnets(context.Background(), []string{"non-existent"})
	require.NoError(t, err)
	require.Equal(t, 0, len(subnets))

	// Test empty subnet IDs list
	subnets, err = api.GetNodesSubnets(context.Background(), []string{})
	require.NoError(t, err)
	require.Equal(t, 0, len(subnets))

	// Test mix of existing and non-existing subnets
	subnets, err = api.GetNodesSubnets(context.Background(), []string{"s-1", "non-existent", "s-2"})
	require.NoError(t, err)
	require.Equal(t, 2, len(subnets))
	require.Equal(t, subnet1.ID, subnets["s-1"].ID)
	require.Equal(t, subnet2.ID, subnets["s-2"].ID)
}
