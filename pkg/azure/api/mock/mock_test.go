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
	api := NewAPI([]*ipamTypes.Subnet{subnet}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}})
	require.NotNil(t, api)

	instances, err := api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
	require.Equal(t, 0, instances.NumInstances())

	vnets, subnets, err := api.GetVpcsAndSubnets(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, len(vnets))
	require.Equal(t, &ipamTypes.VirtualNetwork{ID: "v-1"}, vnets["v-1"])
	require.Equal(t, 1, len(subnets))
	require.Equal(t, subnet, subnets["s-1"])

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
	api := NewAPI([]*ipamTypes.Subnet{}, []*ipamTypes.VirtualNetwork{})
	require.NotNil(t, api)

	mockError := errors.New("error")

	api.SetMockError(GetInstances, mockError)
	_, err := api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	require.ErrorIs(t, err, mockError)

	api.SetMockError(GetVpcsAndSubnets, mockError)
	_, _, err = api.GetVpcsAndSubnets(context.Background())
	require.ErrorIs(t, err, mockError)

	api.SetMockError(AssignPrivateIpAddressesVMSS, mockError)
	err = api.AssignPrivateIpAddressesVMSS(context.Background(), "vmss1", "i-1", "s-1", "eth0", 0)
	require.ErrorIs(t, err, mockError)
}

func TestSetLimiter(t *testing.T) {
	subnet := &ipamTypes.Subnet{ID: "s-1", CIDR: cidr.MustParseCIDR("10.0.0.0/16"), AvailableAddresses: 100}
	api := NewAPI([]*ipamTypes.Subnet{subnet}, []*ipamTypes.VirtualNetwork{{ID: "v-1"}})
	require.NotNil(t, api)

	api.SetLimiter(10.0, 2)
	_, err := api.GetInstances(context.Background(), ipamTypes.SubnetMap{})
	require.NoError(t, err)
}
