// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/alibabacloud/eni/limits"
	eniTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestENIIPAMCapacityAccounting(t *testing.T) {
	assert := assert.New(t)
	limits.Update(map[string]ipamTypes.Limits{
		"ecs.g6.large": {
			IPv4:     10,
			Adapters: 3,
		},
	})
	m := ipamTypes.NewInstanceMap()
	resource := &eniTypes.ENI{
		NetworkInterfaceID: "eni-1",
		PrivateIPSets: []eniTypes.PrivateIPSet{
			{
				Primary: true, // one primary IP
			},
		},
	}
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
				AlibabaCloud: eniTypes.Spec{
					InstanceType: "ecs.g6.large",
				},
			},
		},
	}
	_, stats, err := n.ResyncInterfacesAndIPs(context.Background(), log)
	assert.NoError(err)
	// 3 ENIs, 10 IPs per ENI, 1 primary IP and one ENI is primary.
	assert.Equal(19, stats.NodeCapacity)
}

type mockIPAMNode string

func (m mockIPAMNode) InstanceID() string {
	return string(m)
}
