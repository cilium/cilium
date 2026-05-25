// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func newCapacityTestNode(t *testing.T, ifaces []*types.AzureInterface, usePrimary bool) *Node {
	t.Helper()
	m := ipamTypes.NewInstanceMap()
	for _, iface := range ifaces {
		m.Update("vm1", iface.DeepCopy())
	}
	return &Node{
		node: mockIPAMNode("vm1"),
		manager: &InstancesManager{
			instances:  m,
			api:        apimock.NewAPI(nil),
			usePrimary: usePrimary,
		},
		k8sObj: &v2.CiliumNode{
			Spec: v2.NodeSpec{
				Azure: types.AzureSpec{InterfaceName: "eth0"},
			},
		},
	}
}

func newCapacityTestInterface(name, id, primaryIP string, secondaryIPs ...string) *types.AzureInterface {
	addrs := make([]types.AzureAddress, 0, len(secondaryIPs))
	for _, ip := range secondaryIPs {
		addrs = append(addrs, types.AzureAddress{
			IP:    ip,
			State: types.StateSucceeded,
		})
	}
	iface := &types.AzureInterface{
		Name:          name,
		IP:            primaryIP,
		SecurityGroup: "sg1",
		Subnet:        types.AzureSubnet{ID: "subnet-1"},
		Addresses:     addrs,
		State:         types.StateSucceeded,
	}
	iface.SetID(id)
	return iface
}

func TestENIIPAMCapacityAccounting(t *testing.T) {
	assert := assert.New(t)
	iface := newCapacityTestInterface(
		"eth0",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11",
		"1.1.1.1",
		"1.1.1.2",
	)
	n := newCapacityTestNode(t, []*types.AzureInterface{iface}, false)
	_, stats, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Equal(255, stats.NodeCapacity)
}

func TestENIIPAMCapacityAccountingUsePrimary(t *testing.T) {
	assert := assert.New(t)
	iface := newCapacityTestInterface(
		"eth0",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11",
		"1.1.1.1",
		"1.1.1.2",
	)
	n := newCapacityTestNode(t, []*types.AzureInterface{iface}, true)
	_, stats, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Equal(256, stats.NodeCapacity)
}

func TestENIIPAMCapacityAccountingMultiNIC(t *testing.T) {
	assert := assert.New(t)
	iface1 := newCapacityTestInterface(
		"eth0",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic1",
		"1.1.1.1",
	)
	iface2 := newCapacityTestInterface(
		"eth1",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic2",
		"1.1.2.1",
	)
	n := newCapacityTestNode(t, []*types.AzureInterface{iface1, iface2}, false)
	_, stats, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Equal(254, stats.NodeCapacity)
}

func TestENIIPAMCapacityAccountingMultiNICUsePrimary(t *testing.T) {
	assert := assert.New(t)
	iface1 := newCapacityTestInterface(
		"eth0",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic1",
		"1.1.1.1",
	)
	iface2 := newCapacityTestInterface(
		"eth1",
		"/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/nic2",
		"1.1.2.1",
	)
	n := newCapacityTestNode(t, []*types.AzureInterface{iface1, iface2}, true)
	_, stats, err := n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	assert.NoError(err)
	assert.Equal(256, stats.NodeCapacity)
}

type mockIPAMNode string

func (m mockIPAMNode) InstanceID() string {
	return string(m)
}
