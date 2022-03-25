// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package eni

import (
	"context"
	"fmt"
	"time"

	"gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/alibabacloud/api/mock"
	"github.com/cilium/cilium/pkg/alibabacloud/eni/limits"
	eniTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	"github.com/cilium/cilium/pkg/alibabacloud/utils"
	"github.com/cilium/cilium/pkg/ipam"
	metricsmock "github.com/cilium/cilium/pkg/ipam/metrics/mock"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	k8sapi     = &k8sMock{}
	alibabaAPI *mock.API
	instances  *InstancesManager
	metricsapi = metricsmock.NewMockMetrics()
)

func (e *ENISuite) SetUpTest(c *check.C) {
	limits.Update(map[string]ipamTypes.Limits{
		"ecs.g7ne.large":    {Adapters: 3, IPv4: 10, IPv6: 0},
		"ecs.g7ne.24xlarge": {Adapters: 15, IPv4: 50, IPv6: 0},
	})

	metricsapi = metricsmock.NewMockMetrics()
	alibabaAPI = mock.NewAPI(subnets, vpcs, securityGroups)
	c.Assert(alibabaAPI, check.Not(check.IsNil))
	alibabaAPI.UpdateENIs(primaryENIs)
	instances = NewInstancesManager(alibabaAPI)
	c.Assert(instances, check.Not(check.IsNil))
}

func (e *ENISuite) TearDownTest(c *check.C) {
	metricsapi = nil
	alibabaAPI = nil
	instances = nil
}

func (e *ENISuite) TestGetMaximumAllocatableIPv4(c *check.C) {
	n := &Node{}
	n.k8sObj = newCiliumNode("node", "i-1", "ecs.g7ne.24xlarge", "cn-hangzhou-i", "vpc-1")
	c.Assert(n.GetMaximumAllocatableIPv4(), check.Equals, 700)
}

func (e *ENISuite) TestCreateInterface(c *check.C) {
	alibabaAPI.UpdateENIs(primaryENIs)
	instances.Resync(context.TODO())

	mngr, err := ipam.NewNodeManager(instances, k8sapi, metricsapi, 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	mngr.Update(newCiliumNode("node1", "i-1", "ecs.g7ne.large", "cn-hangzhou-i", "vpc-1"))
	mngr.Update(newCiliumNode("node2", "i-2", "ecs.g7ne.large", "cn-hangzhou-h", "vpc-1"))
	names := mngr.GetNames()
	c.Assert(len(names), check.Equals, 2)

	err = testutils.WaitUntil(func() bool {
		return mngr.InstancesAPIIsReady()
	}, 10*time.Second)
	c.Assert(err, check.IsNil)

	instances.ForeachInstance("i-1", func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
		e, ok := rev.Resource.(*eniTypes.ENI)
		if !ok {
			return fmt.Errorf("resource is not ENI type")
		}
		switch e.Type {
		case eniTypes.ENITypeSecondary:
			c.Assert(utils.GetENIIndexFromTags(e.Tags), check.Equals, 1)
		case eniTypes.ENITypePrimary:
			c.Assert(utils.GetENIIndexFromTags(e.Tags), check.Equals, 0)
		}
		return nil
	})

	toAlloc, _, err := mngr.Get("node1").Ops().CreateInterface(context.Background(), &ipam.AllocationAction{
		MaxIPsToAllocate:    10,
		AvailableInterfaces: 2,
	}, log)
	c.Assert(err, check.IsNil)
	c.Assert(toAlloc, check.Equals, 10)

	toAlloc, _, err = mngr.Get("node1").Ops().CreateInterface(context.Background(), &ipam.AllocationAction{
		MaxIPsToAllocate:    11,
		AvailableInterfaces: 1,
	}, log)
	c.Assert(err, check.IsNil)
	c.Assert(toAlloc, check.Equals, 10)
}

func (e *ENISuite) TestPrepareIPAllocation(c *check.C) {
	alibabaAPI.UpdateENIs(primaryENIs)
	instances.Resync(context.TODO())

	mngr, err := ipam.NewNodeManager(instances, k8sapi, metricsapi, 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	mngr.Update(newCiliumNode("node1", "i-1", "ecs.g7ne.large", "cn-hangzhou-i", "vpc-1"))
	a, err := mngr.Get("node1").Ops().PrepareIPAllocation(log)
	c.Assert(err, check.IsNil)
	c.Assert(a.AvailableInterfaces, check.Equals, 2)

	// create one eni
	toAlloc, _, err := mngr.Get("node1").Ops().CreateInterface(context.Background(), &ipam.AllocationAction{
		MaxIPsToAllocate:    10,
		AvailableInterfaces: 2,
	}, log)
	c.Assert(err, check.IsNil)
	c.Assert(toAlloc, check.Equals, 10)

	// one eni left
	a, err = mngr.Get("node1").Ops().PrepareIPAllocation(log)
	c.Assert(err, check.IsNil)
	c.Assert(a.AvailableInterfaces, check.Equals, 1)
}

func (e *ENISuite) TestNode_allocENIIndex(c *check.C) {
	n := Node{enis: map[string]eniTypes.ENI{
		"eni-1": {
			InstanceID: "eni-1",
			Type:       eniTypes.ENITypePrimary,
			Tags:       nil,
		},
	}}
	index, err := n.allocENIIndex()
	c.Assert(err, check.IsNil)
	c.Assert(index, check.Equals, 1)

	n.enis["eni-2"] = eniTypes.ENI{
		InstanceID: "eni-2",
		Type:       eniTypes.ENITypeSecondary,
		Tags:       map[string]string{"cilium-eni-index": "1"},
	}
	index, err = n.allocENIIndex()
	c.Assert(err, check.IsNil)
	c.Assert(index, check.Equals, 2)
}

type k8sMock struct{}

func (k *k8sMock) Create(node *v2.CiliumNode) (*v2.CiliumNode, error) {
	return nil, nil
}

func (k *k8sMock) Update(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	return nil, nil
}

func (k *k8sMock) UpdateStatus(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	return nil, nil
}

func (k *k8sMock) Get(node string) (*v2.CiliumNode, error) {
	return &v2.CiliumNode{}, nil
}

func newCiliumNode(node, instanceID, instanceType, az, vpcID string) *v2.CiliumNode {
	cn := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: node, Namespace: "default"},
		Spec: v2.NodeSpec{
			InstanceID: instanceID,
			AlibabaCloud: eniTypes.Spec{
				InstanceType:     instanceType,
				VPCID:            vpcID,
				AvailabilityZone: az,
			},
			IPAM: ipamTypes.IPAMSpec{
				Pool: ipamTypes.AllocationMap{},
			},
		},
		Status: v2.NodeStatus{
			IPAM: ipamTypes.IPAMStatus{
				Used: ipamTypes.AllocationMap{},
			},
		},
	}

	return cn
}
