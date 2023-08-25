// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestENIIPAMCapacityAccounting(t *testing.T) {
	assert := assert.New(t)
	m := ipamTypes.NewInstanceMap()
	resource := &types.AzureInterface{
		Name:          "eth0",
		SecurityGroup: "sg1",
		Addresses: []types.AzureAddress{
			{
				IP:     "1.1.1.1",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss11/virtualMachines/vm1/networkInterfaces/vmss11")
	m.Update("vm1", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})

	n := &Node{
		node: mockIPAMNode("vm1"),
		manager: &InstancesManager{
			instances: m,
		},
		k8sObj: &v2.CiliumNode{
			Spec: v2.NodeSpec{
				Azure: types.AzureSpec{
					InterfaceName: "eth0",
				},
			},
		},
	}
	_, stats, err := n.ResyncInterfacesAndIPs(context.Background(), log)
	assert.NoError(err)
	assert.Equal(255, stats.NodeCapacity)
}

type mockIPAMNode string

func (m mockIPAMNode) InstanceID() string {
	return string(m)
}
