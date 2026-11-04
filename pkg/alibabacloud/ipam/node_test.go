// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	metricsmock "github.com/cilium/cilium/operator/pkg/ipam/metrics/mock"
	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	"github.com/cilium/cilium/pkg/alibabacloud/api/mock"
	"github.com/cilium/cilium/pkg/alibabacloud/ipam/limits"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	iputil "github.com/cilium/cilium/pkg/ip"
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
	logger := hivetest.Logger(tb)
	instances = NewInstancesManager(logger, alibabaAPI)
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
	logger := hivetest.Logger(t)

	alibabaAPI.UpdateENIs(primaryENIs)
	_, err := instances.Resync(t.Context())
	require.NoError(t, err)

	mngr, err := nodemanager.NewNodeManager(logger, instances, k8sapi, metricsapi, 10, false, 0, false)
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

	instances.ForeachInstance("i-1", func(instanceID, interfaceID string, iface ipamTypes.Interface) error {
		e, ok := iface.(*types.ENI)
		if !ok {
			return fmt.Errorf("resource is not ENI type")
		}
		switch e.Type {
		case types.ENITypeSecondary:
			require.Equal(t, 1, types.GetENIIndexFromTags(logger, e.Tags))
		case types.ENITypePrimary:
			require.Equal(t, 0, types.GetENIIndexFromTags(logger, e.Tags))
		}
		return nil
	})

	toAlloc, _, err := mngr.Get("node1").Ops().CreateInterface(t.Context(), &nodemanager.AllocationAction{
		IPv4: nodemanager.IPAllocationAction{
			MaxIPsToAllocate: 10,
		},
		EmptyInterfaceSlots: 2,
	}, logger)
	require.NoError(t, err)
	require.Equal(t, 10, toAlloc)

	toAlloc, _, err = mngr.Get("node1").Ops().CreateInterface(t.Context(), &nodemanager.AllocationAction{
		IPv4: nodemanager.IPAllocationAction{
			MaxIPsToAllocate: 11,
		},
		EmptyInterfaceSlots: 1,
	}, logger)
	require.NoError(t, err)
	require.Equal(t, 10, toAlloc)
}

func TestCandidateAndEmptyInterfaces(t *testing.T) {
	setup(t)
	logger := hivetest.Logger(t)

	alibabaAPI.UpdateENIs(primaryENIs)
	_, err := instances.Resync(t.Context())
	require.NoError(t, err)

	mngr, err := nodemanager.NewNodeManager(logger, instances, k8sapi, metricsapi, 10, false, 0, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)
	// Set PreAllocate as 1
	cn := newCiliumNodeWithIpamParams("node3", "i-3", "ecs.g8m.small", "cn-hangzhou-h", "vpc-1", 1, 0, 0)
	cn.Spec.AlibabaCloud.VSwitches = []string{"vsw-2"}
	mngr.Upsert(cn)

	n := &Node{logger: logger}
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
	logger := hivetest.Logger(t)

	alibabaAPI.UpdateENIs(primaryENIs)
	_, err := instances.Resync(t.Context())
	require.NoError(t, err)

	mngr, err := nodemanager.NewNodeManager(logger, instances, k8sapi, metricsapi, 10, false, 0, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)
	mngr.SetInstancesAPIReadiness(false) // to avoid the manager background jobs starting and racing us.

	mngr.Upsert(newCiliumNode("node1", "i-1", "ecs.g7ne.large", "cn-hangzhou-i", "vpc-1"))
	a, err := mngr.Get("node1").Ops().PrepareIPAllocation(logger)
	require.NoError(t, err)
	require.Equal(t, 2, a.EmptyInterfaceSlots+a.IPv4.InterfaceCandidates, "empty: %v, candidates: %v", a.EmptyInterfaceSlots, a.IPv4.InterfaceCandidates)

	// create one eni
	toAlloc, _, err := mngr.Get("node1").Ops().CreateInterface(t.Context(), &nodemanager.AllocationAction{
		IPv4: nodemanager.IPAllocationAction{
			MaxIPsToAllocate: 10,
		},
		EmptyInterfaceSlots: 2,
	}, logger)
	require.NoError(t, err)
	require.Equal(t, 10, toAlloc)

	// one eni left
	a, err = mngr.Get("node1").Ops().PrepareIPAllocation(logger)
	require.NoError(t, err)
	require.Equal(t, 1, a.EmptyInterfaceSlots, "empty: %v, candidates: %v", a.EmptyInterfaceSlots, a.IPv4.InterfaceCandidates)
}

func TestNode_allocENIIndex(t *testing.T) {
	n := Node{enis: map[string]types.ENI{
		"eni-1": {
			InstanceID: "eni-1",
			Type:       types.ENITypePrimary,
			Tags:       nil,
		},
	}}
	index, err := n.allocENIIndex()
	require.NoError(t, err)
	require.Equal(t, 1, index)

	n.enis["eni-2"] = types.ENI{
		InstanceID: "eni-2",
		Type:       types.ENITypeSecondary,
		Tags:       map[string]string{"cilium-eni-index": "1"},
	}
	index, err = n.allocENIIndex()
	require.NoError(t, err)
	require.Equal(t, 2, index)
}

func TestAttachedCIDRsAndPrepareRelease(t *testing.T) {
	address := func(s string, primary bool) types.PrivateIPSet {
		return types.PrivateIPSet{PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr(s)), Primary: primary}
	}
	n := &Node{enis: map[string]types.ENI{
		"host": {Type: types.ENITypePrimary, PrivateIPSets: []types.PrivateIPSet{address("10.0.0.1", true), address("10.0.0.2", false)}},
		"eni-1": {
			Type:             types.ENITypeSecondary,
			PrimaryIPAddress: iputil.AddrFrom(netip.MustParseAddr("10.0.0.3")),
			VSwitch:          types.VSwitch{VSwitchID: "vsw-1"},
			// Also protect the primary address if its per-address flag is absent.
			PrivateIPSets: []types.PrivateIPSet{address("10.0.0.3", false), address("10.0.0.4", false), address("10.0.0.5", true), {}, address("2001:db8::1", false)},
		},
		"eni-2": {Type: types.ENITypeSecondary, VSwitch: types.VSwitch{VSwitchID: "vsw-2"}, PrivateIPSets: []types.PrivateIPSet{address("10.0.0.6", false), address("10.0.0.7", false)}},
	}}
	prefixes := func(addrs ...string) []netip.Prefix {
		var result []netip.Prefix
		for _, addr := range addrs {
			result = append(result, netip.MustParsePrefix(addr))
		}
		return result
	}
	require.ElementsMatch(t, prefixes("10.0.0.3/32", "10.0.0.4/32", "10.0.0.5/32", "10.0.0.6/32", "10.0.0.7/32"), n.GetAttachedCIDRs())
	require.Empty(t, n.PrepareCIDRRelease(nil))
	actions := n.PrepareCIDRRelease(prefixes("10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32", "10.0.0.4/32", "10.0.0.4/32", "10.0.0.5/32", "10.0.0.6/32", "10.0.0.99/32", "10.0.0.0/24", "2001:db8::1/128"))
	require.ElementsMatch(t, []*nodemanager.ReleaseAction{
		{InterfaceID: "eni-1", PoolID: ipamTypes.PoolID("vsw-1"), CIDRsToRelease: prefixes("10.0.0.4/32")},
		{InterfaceID: "eni-2", PoolID: ipamTypes.PoolID("vsw-2"), CIDRsToRelease: prefixes("10.0.0.6/32")},
	}, actions)
}

type releaseAPIMock struct {
	AlibabaCloudAPI
	calls     int
	eniID     string
	addresses []string
	err       error
}

func (a *releaseAPIMock) UnassignPrivateIPAddresses(_ context.Context, eniID string, addresses []string) error {
	a.calls++
	a.eniID = eniID
	a.addresses = addresses
	return a.err
}

func TestReleaseCIDRs(t *testing.T) {
	wantErr := errors.New("ECS release failed")
	for _, fail := range []bool{false, true} {
		api := &releaseAPIMock{}
		if fail {
			api.err = wantErr
		}
		n := &Node{manager: &InstancesManager{api: api, instances: ipamTypes.NewInstanceMap()}}
		action := &nodemanager.ReleaseAction{
			InterfaceID:    "eni-1",
			CIDRsToRelease: []netip.Prefix{netip.MustParsePrefix("10.0.0.4/32"), netip.MustParsePrefix("10.0.0.5/32")},
		}
		// The node manager can narrow the action after preparation. Never use
		// IPsToRelease from the old CRD protocol instead of the filtered CIDRs.
		action.IPsToRelease = []string{"10.0.0.99"}
		released, err := n.ReleaseCIDRs(t.Context(), action)
		if fail {
			require.ErrorIs(t, err, wantErr)
			require.Empty(t, released)
		} else {
			require.NoError(t, err)
			require.Equal(t, action.CIDRsToRelease, released)
		}
		require.Equal(t, "eni-1", api.eniID)
		require.Equal(t, []string{"10.0.0.4", "10.0.0.5"}, api.addresses)
	}
	for _, prefix := range []string{"10.0.0.0/24", "2001:db8::1/128"} {
		api := &releaseAPIMock{}
		n := &Node{manager: &InstancesManager{api: api, instances: ipamTypes.NewInstanceMap()}}
		_, err := n.ReleaseCIDRs(t.Context(), &nodemanager.ReleaseAction{CIDRsToRelease: []netip.Prefix{netip.MustParsePrefix(prefix)}})
		require.Error(t, err)
		require.Zero(t, api.calls)
	}
	api := &releaseAPIMock{}
	n := &Node{manager: &InstancesManager{api: api, instances: ipamTypes.NewInstanceMap()}}
	released, err := n.ReleaseCIDRs(t.Context(), &nodemanager.ReleaseAction{})
	require.NoError(t, err)
	require.Empty(t, released)
	require.Zero(t, api.calls)
}

func TestReleaseCIDRsUpdatesPublishedStatus(t *testing.T) {
	for _, fail := range []bool{false, true} {
		api := &releaseAPIMock{}
		if fail {
			api.err = errors.New("release failed")
		}
		manager := &InstancesManager{api: api, instances: ipamTypes.NewInstanceMap()}
		eni := &types.ENI{
			NetworkInterfaceID: "eni-1",
			Type:               types.ENITypeSecondary,
			PrivateIPSets: []types.PrivateIPSet{
				{PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("10.0.0.3")), Primary: true},
				{PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("10.0.0.4"))},
			},
		}
		// Seed the existing instance; UpdateENI only updates discovered instances.
		manager.instances.Update("i-1", eni)
		cn := newCiliumNode("node1", "i-1", "ecs.g7ne.large", "cn-hangzhou-i", "vpc-1")
		// The node manager has not yet bound its CiliumNode when CreateNode is called.
		n := manager.CreateNode(cn, &nodemanager.Node{}).(*Node)
		require.Equal(t, "i-1", n.instanceID)
		_, err := n.ReleaseCIDRs(t.Context(), &nodemanager.ReleaseAction{
			InterfaceID: "eni-1", CIDRsToRelease: []netip.Prefix{netip.MustParsePrefix("10.0.0.4/32")},
		})
		n.PopulateStatusFields(cn)
		if fail {
			require.Error(t, err)
			require.Equal(t, eni.PrivateIPSets, cn.Status.AlibabaCloud.ENIs["eni-1"].PrivateIPSets)
		} else {
			require.NoError(t, err)
			require.Equal(t, eni.PrivateIPSets[:1], cn.Status.AlibabaCloud.ENIs["eni-1"].PrivateIPSets)
		}
		require.Len(t, eni.PrivateIPSets, 2, "cache updates must not mutate existing snapshots")
	}
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
			AlibabaCloud: types.Spec{
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
			AlibabaCloud: types.Spec{
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

func reachedAddressesNeeded(mngr *nodemanager.NodeManager, nodeName string, needed int) (success bool) {
	if node := mngr.Get(nodeName); node != nil {
		success = node.GetNeededAddresses() == needed
	}
	return
}
