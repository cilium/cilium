// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/alibabacloud/api/mock"
	"github.com/cilium/cilium/pkg/alibabacloud/eni/limits"
	eniTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	"github.com/cilium/cilium/pkg/alibabacloud/utils"
	"github.com/cilium/cilium/pkg/ipam"
	metricsmock "github.com/cilium/cilium/pkg/ipam/metrics/mock"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	k8sapi     = &k8sMock{}
	alibabaAPI *mock.API
	instances  *InstancesManager
	metricsapi = metricsmock.NewMockMetrics()
)

func setup(tb testing.TB) {
	tb.Helper()
	limits.Update(map[string]ipamTypes.Limits{
		"ecs.g7ne.large":    {Adapters: 3, IPv4: 10, IPv6: 0},
		"ecs.g7ne.24xlarge": {Adapters: 15, IPv4: 50, IPv6: 0},
		"ecs.g8m.small":     {Adapters: 2, IPv4: 3, IPv6: 0},
	})

	metricsapi = metricsmock.NewMockMetrics()
	alibabaAPI = mock.NewAPI(subnets, vpcs, securityGroups)
	require.NotNil(tb, alibabaAPI)
	alibabaAPI.UpdateENIs(primaryENIs)
	instances = NewInstancesManager(logging.DefaultSlogLogger, alibabaAPI)
	require.NotNil(tb, instances)

	tb.Cleanup(func() {
		metricsapi = nil
		alibabaAPI = nil
		instances = nil
	})
}

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	setup(t)

	n := &Node{}
	n.k8sObj = newCiliumNode("node", "i-1", "ecs.g7ne.24xlarge", "cn-hangzhou-i", "vpc-1")
	require.Equal(t, 700, n.GetMaximumAllocatableIPv4())
}

func TestCreateInterface(t *testing.T) {
	setup(t)

	alibabaAPI.UpdateENIs(primaryENIs)
	instances.Resync(t.Context())

	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	mngr.Upsert(newCiliumNode("node1", "i-1", "ecs.g7ne.large", "cn-hangzhou-i", "vpc-1"))
	mngr.Upsert(newCiliumNode("node2", "i-2", "ecs.g7ne.large", "cn-hangzhou-h", "vpc-1"))
	names := mngr.GetNames()
	require.Len(t, names, 2)

	err = testutils.WaitUntil(func() bool {
		return mngr.InstancesAPIIsReady()
	}, 10*time.Second)
	require.NoError(t, err)

	instances.ForeachInstance("i-1", func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
		e, ok := rev.Resource.(*eniTypes.ENI)
		if !ok {
			return fmt.Errorf("resource is not ENI type")
		}
		switch e.Type {
		case eniTypes.ENITypeSecondary:
			require.Equal(t, 1, utils.GetENIIndexFromTags(logging.DefaultSlogLogger, e.Tags))
		case eniTypes.ENITypePrimary:
			require.Equal(t, 0, utils.GetENIIndexFromTags(logging.DefaultSlogLogger, e.Tags))
		}
		return nil
	})

	toAlloc, _, err := mngr.Get("node1").Ops().CreateInterface(t.Context(), &ipam.AllocationAction{
		IPv4: ipam.IPAllocationAction{
			MaxIPsToAllocate: 10,
		},
		EmptyInterfaceSlots: 2,
	}, logging.DefaultSlogLogger)
	require.NoError(t, err)
	require.Equal(t, 10, toAlloc)

	toAlloc, _, err = mngr.Get("node1").Ops().CreateInterface(t.Context(), &ipam.AllocationAction{
		IPv4: ipam.IPAllocationAction{
			MaxIPsToAllocate: 11,
		},
		EmptyInterfaceSlots: 1,
	}, logging.DefaultSlogLogger)
	require.NoError(t, err)
	require.Equal(t, 10, toAlloc)
}

func TestCandidateAndEmptyInterfaces(t *testing.T) {
	setup(t)

	alibabaAPI.UpdateENIs(primaryENIs)
	instances.Resync(t.Context())

	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)
	// Set PreAllocate as 1
	cn := newCiliumNodeWithIpamParams("node3", "i-3", "ecs.g8m.small", "cn-hangzhou-h", "vpc-1", 1, 0, 0)
	cn.Spec.AlibabaCloud.VSwitches = []string{"vsw-2"}
	mngr.Upsert(cn)

	n := &Node{logger: logging.DefaultSlogLogger}
	n.k8sObj = cn
	// Primary ENI excluded, max allocatable = 3 ( 1 (ENI) * 3 (IPv4/ENI) )
	require.Equal(t, 3, n.GetMaximumAllocatableIPv4())

	// Wait for IPs to become available
	require.Eventually(t, func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second, 1*time.Second)

	node3 := mngr.Get("node3")
	a, err := node3.Ops().PrepareIPAllocation(n.logger)
	require.NoError(t, err)
	// 1 ENI attached, 1/3 IPs allocated, 0 empty slots left
	require.Equal(t, 1, a.IPv4.InterfaceCandidates)
	require.Equal(t, 0, a.EmptyInterfaceSlots)
	require.Equal(t, 1, node3.Stats().IPv4.AvailableIPs)
}

func TestPrepareIPAllocation(t *testing.T) {
	setup(t)

	alibabaAPI.UpdateENIs(primaryENIs)
	instances.Resync(t.Context())

	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)
	mngr.SetInstancesAPIReadiness(false) // to avoid the manager background jobs starting and racing us.

	mngr.Upsert(newCiliumNode("node1", "i-1", "ecs.g7ne.large", "cn-hangzhou-i", "vpc-1"))
	a, err := mngr.Get("node1").Ops().PrepareIPAllocation(logging.DefaultSlogLogger)
	require.NoError(t, err)
	require.Equal(t, 2, a.EmptyInterfaceSlots+a.IPv4.InterfaceCandidates, "empty: %v, candidates: %v", a.EmptyInterfaceSlots, a.IPv4.InterfaceCandidates)

	// create one eni
	toAlloc, _, err := mngr.Get("node1").Ops().CreateInterface(t.Context(), &ipam.AllocationAction{
		IPv4: ipam.IPAllocationAction{
			MaxIPsToAllocate: 10,
		},
		EmptyInterfaceSlots: 2,
	}, logging.DefaultSlogLogger)
	require.NoError(t, err)
	require.Equal(t, 10, toAlloc)

	// one eni left
	a, err = mngr.Get("node1").Ops().PrepareIPAllocation(logging.DefaultSlogLogger)
	require.NoError(t, err)
	require.Equal(t, 1, a.EmptyInterfaceSlots, "empty: %v, candidates: %v", a.EmptyInterfaceSlots, a.IPv4.InterfaceCandidates)
}

func TestNode_allocENIIndex(t *testing.T) {
	n := Node{enis: map[string]eniTypes.ENI{
		"eni-1": {
			InstanceID: "eni-1",
			Type:       eniTypes.ENITypePrimary,
			Tags:       nil,
		},
	}}
	index, err := n.allocENIIndex()
	require.NoError(t, err)
	require.Equal(t, 1, index)

	n.enis["eni-2"] = eniTypes.ENI{
		InstanceID: "eni-2",
		Type:       eniTypes.ENITypeSecondary,
		Tags:       map[string]string{"cilium-eni-index": "1"},
	}
	index, err = n.allocENIIndex()
	require.NoError(t, err)
	require.Equal(t, 2, index)
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

func newCiliumNodeWithIpamParams(node, instanceID, instanceType, az, vpcID string, preAllocate, minAllocate, maxAllocate int) *v2.CiliumNode {
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
				Pool:        ipamTypes.AllocationMap{},
				PreAllocate: preAllocate,
				MinAllocate: minAllocate,
				MaxAllocate: maxAllocate,
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

func reachedAddressesNeeded(mngr *ipam.NodeManager, nodeName string, needed int) (success bool) {
	if node := mngr.Get(nodeName); node != nil {
		success = node.GetNeededAddresses() == needed
	}
	return
}
