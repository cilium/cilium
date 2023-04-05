// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestENIIPAMCapacityAccounting(t *testing.T) {
	assert := assert.New(t)
	instanceID := "i-000"
	cn := newCiliumNode("node1", withInstanceType("m5a.large"),
		func(cn *v2.CiliumNode) {
			cn.Spec.InstanceID = instanceID
		},
	)
	im := ipamTypes.NewInstanceMap()
	im.Update(instanceID, ipamTypes.InterfaceRevision{
		Resource: &eniTypes.ENI{},
	})

	ipamNode := &mockIPAMNode{
		instanceID: "i-000",
	}
	n := &Node{
		node:   ipamNode,
		k8sObj: cn,
		manager: &InstancesManager{
			instances: im,
		},
		enis: map[string]eniTypes.ENI{"eni-a": {}},
	}

	ipamNode.SetOpts(n)
	ipamNode.SetPoolMaintainer(&mockMaintainer{})
	n.node = ipamNode

	_, stats, err := n.ResyncInterfacesAndIPs(context.Background(), log)
	assert.NoError(err)
	// m5a.large = 10 IPs per ENI, 3 ENIs.
	// Accounting for primary ENI IPs, we should be able to allocate (10-1)*3=27 IPs.
	assert.Equal(27, stats.NodeCapacity)

	cn.Spec.ENI.UsePrimaryAddress = new(bool)
	*cn.Spec.ENI.UsePrimaryAddress = true
	_, stats, err = n.ResyncInterfacesAndIPs(context.Background(), log)
	assert.NoError(err)
	// In this case, we disable using allocated primary IP,
	// so we should be able to allocate 10*3=30 IPs.
	assert.Equal(30, stats.NodeCapacity)

	ipamNode.prefixDelegation = true
	// Note: m5a.large is a nitro instance, so it supports prefix delegation.
	_, stats, err = n.ResyncInterfacesAndIPs(context.Background(), log)
	assert.NoError(err)
	// m5a.large = 10 IPs per ENI, 3 ENIs.
	// Accounting for primary ENI IPs, we should be able to allocate (10-1)*3=27 IPs.
	//
	// In this case, we have prefix delegation enabled.
	// Thus we have 16 addr * 10 addr * 3 ENIs = 480 IPs.
	assert.Equal(480, stats.NodeCapacity)

	// Lets turn off UsePrimaryAddress.
	*cn.Spec.ENI.UsePrimaryAddress = false
	_, stats, err = n.ResyncInterfacesAndIPs(context.Background(), log)
	assert.NoError(err)
	// In this case, we have prefix delegation enabled.
	// Thus we have 16 addr * 9 addr * 3 ENIs = 432 IPs.
	assert.Equal(432, stats.NodeCapacity)

	// Finally, lets disable prefix delegation and simulate the case of
	// leftover delegated IPs.
	ipamNode.prefixDelegation = false
	n.enis["eni-a"] = eniTypes.ENI{
		ID:       "eni-a",
		Prefixes: []string{"10.0.0.1/28"},
	}
	n.manager.instances.Update("i-000", ipamTypes.InterfaceRevision{
		Resource: &eniTypes.ENI{
			ID:       "eni-a",
			Prefixes: []string{"10.0.0.1/28"},
		},
	})

	// Finally, we have the case where an eni has a leftover prefix available.
	// Thus, we add an additional 16 IPs to the capacity.
	_, stats, err = n.ResyncInterfacesAndIPs(context.Background(), log)
	assert.NoError(err)
	assert.Equal(27+16-1, stats.NodeCapacity)
}

// mocks ipamNodeActions interface
type mockIPAMNode struct {
	instanceID       string
	prefixDelegation bool
}

func (m *mockIPAMNode) SetOpts(ipam.NodeOperations)           {}
func (m *mockIPAMNode) SetPoolMaintainer(ipam.PoolMaintainer) {}
func (m *mockIPAMNode) UpdatedResource(*v2.CiliumNode) bool   { panic("not impl") }
func (m *mockIPAMNode) Update(*v2.CiliumNode)                 {}
func (m *mockIPAMNode) InstanceID() string                    { return m.instanceID }
func (m *mockIPAMNode) IsPrefixDelegationEnabled() bool       { return m.prefixDelegation }
func (m *mockIPAMNode) Ops() ipam.NodeOperations              { panic("not impl") }
func (m *mockIPAMNode) SetRunning(_ bool)                     { panic("not impl") }

var _ ipamNodeActions = (*mockIPAMNode)(nil)

type mockMaintainer struct{}

func (m *mockMaintainer) Trigger()  {}
func (m *mockMaintainer) Shutdown() {}
