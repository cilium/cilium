// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	ec2mock "github.com/cilium/cilium/pkg/aws/ec2/mock"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/ipam"
	metricsmock "github.com/cilium/cilium/pkg/ipam/metrics/mock"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/testutils"
	testipam "github.com/cilium/cilium/pkg/testutils/ipam"
)

var (
	testSubnet = &ipamTypes.Subnet{
		ID:                 "s-1",
		AvailabilityZone:   "us-west-1",
		VirtualNetworkID:   "vpc-1",
		AvailableAddresses: 200,
		Tags:               ipamTypes.Tags{"k": "v"},
	}
	testVpc = &ipamTypes.VirtualNetwork{
		ID:          "vpc-1",
		PrimaryCIDR: "10.10.0.0/16",
	}
	testSecurityGroups = []*types.SecurityGroup{
		{
			ID:    "sg-1",
			VpcID: "vpc-1",
			Tags:  ipamTypes.Tags{"test-sg-1": "yes"},
		},
		{
			ID:    "sg-2",
			VpcID: "vpc-1",
			Tags:  ipamTypes.Tags{"test-sg-2": "yes"},
		},
	}
	testRouteTables = []*ipamTypes.RouteTable{
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
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-3": {},
				"subnet-4": {},
			},
		},
	}
	k8sapi     = &k8sMock{}
	metricsapi = metricsmock.NewMockMetrics()
)

func setup(tb testing.TB) {
	metricsapi = metricsmock.NewMockMetrics()

	tb.Cleanup(func() {
		metricsapi = nil
	})
}

func TestGetNodeNames(t *testing.T) {
	setup(t)

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	node1 := newCiliumNode("node1")
	mngr.Upsert(node1)

	names := mngr.GetNames()
	require.Len(t, names, 1)
	require.Equal(t, "node1", names[0])

	mngr.Upsert(newCiliumNode("node2"))

	names = mngr.GetNames()
	require.Len(t, names, 2)

	mngr.Delete(node1)

	names = mngr.GetNames()
	require.Len(t, names, 1)
	require.Equal(t, "node2", names[0])
}

func TestNodeManagerGet(t *testing.T) {
	setup(t)

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	node1 := newCiliumNode("node1")
	mngr.Upsert(node1)

	require.NotNil(t, mngr.Get("node1"))
	require.Nil(t, mngr.Get("node2"))

	mngr.Delete(node1)
	require.Nil(t, mngr.Get("node1"))
	require.Nil(t, mngr.Get("node2"))
}

// TestNodeManagerDefaultAllocation tests allocation with default parameters
//
// - m5.large (3x ENIs, 2x10-2 IPs)
// - MinAllocate 0
// - MaxAllocate 0
// - PreAllocate 8
// - FirstInterfaceIndex 0
func TestNodeManagerDefaultAllocation(t *testing.T) {
	setup(t)

	const instanceID = "i-testNodeManagerDefaultAllocation-0"

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node1", withTestDefaults(), withInstanceID(instanceID), withInstanceType("m5.large"), withIPAMPreAllocate(8))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))
	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 8, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 7 out of 8 IPs
	mngr.Upsert(updateCiliumNode(cn, 8, 7))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node = mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 15, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 7, node.Stats().IPv4.UsedIPs)
}

// TestNodeManagerPrefixDelegation tests allocation with default parameters
//
// - m5.large (3x ENIs, 2x10-2 IPs)
// - MinAllocate 0
// - MaxAllocate 0
// - PreAllocate 8
// - FirstInterfaceIndex 0
func TestNodeManagerPrefixDelegation(t *testing.T) {
	setup(t)

	const instanceID = "i-testNodeManagerDefaultAllocation-0"

	pdTestSubnet := *testSubnet
	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{&pdTestSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, true)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, true)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node1", withInstanceID(instanceID), withInstanceType("m5.large"), withIPAMPreAllocate(8))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 16, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 12 out of 16 IPs
	mngr.Upsert(updateCiliumNode(cn, 16, 12))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node = mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 32, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 12, node.Stats().IPv4.UsedIPs)

	node.Ops().PopulateStatusFields(cn)

	var totalPrefixes int
	for _, eni := range cn.Status.ENI.ENIs {
		totalPrefixes += len(eni.Prefixes)
	}
	require.Equal(t, 2, totalPrefixes)

	// Test fallback to /32 IPs when /28 blocks aren't available
	//
	// Set available IPs to a value insufficient to allocate a /28 block, but enough for /32 IPs to resolve
	// pre-allocate deficit.
	pdTestSubnet.AvailableAddresses = 15
	ec2api.UpdateSubnets([]*ipamTypes.Subnet{&pdTestSubnet})

	// Use 25 out of 32 IPs
	mngr.Upsert(updateCiliumNode(cn, 32, 25))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node = mngr.Get("node1")
	require.NotNil(t, node)
	// Should allocate only 1 additional IP after fallback, not an entire /28 prefix
	require.Equal(t, 33, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 25, node.Stats().IPv4.UsedIPs)
}

// TestNodeManagerENIWithSGTags tests ENI allocation + association with a SG based on tags
//
// - m5.large (3x ENIs, 2x10-2 IPs)
// - MinAllocate 0
// - MaxAllocate 0
// - PreAllocate 8
// - FirstInterfaceIndex 0
func TestNodeManagerENIWithSGTags(t *testing.T) {
	setup(t)

	const instanceID = "i-testNodeManagerDefaultAllocation-0"

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node wait for IPs to become available
	sgTags := map[string]string{
		"test-sg-1": "yes",
	}
	cn := newCiliumNode("node1", withTestDefaults(), withInstanceID(instanceID), withInstanceType("m5.large"),
		withSecurityGroupTags(sgTags), withIPAMPreAllocate(8))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 8, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 7 out of 8 IPs
	mngr.Upsert(updateCiliumNode(cn, 8, 7))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node = mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 15, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 7, node.Stats().IPv4.UsedIPs)

	// At this point we have 2 enis, make a local copy
	// and remove eth0 from the map
	eniNode, castOK := node.Ops().(*Node)
	require.True(t, castOK)
	eniNode.mutex.RLock()
	for id, eni := range eniNode.enis {
		if id != eniID1 {
			require.Equal(t, []string{"sg-1"}, eni.SecurityGroups)
		}
	}
	eniNode.mutex.RUnlock()
}

// TestNodeManagerMinAllocate20 tests MinAllocate without PreAllocate
//
// - m5.4xlarge (8x ENIs, 7x30-7 IPs)
// - MinAllocate 10
// - MaxAllocate 0
// - PreAllocate -1
// - FirstInterfaceIndex 0
func TestNodeManagerMinAllocate20(t *testing.T) {
	setup(t)

	const instanceID = "i-testNodeManagerMinAllocate20-1"

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node2", withInstanceID(instanceID), withInstanceType("m5.4xlarge"), withIPAMPreAllocate(-1), withIPAMMinAllocate(10))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node := mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	mngr.Upsert(updateCiliumNode(cn, 10, 8))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 8, node.Stats().IPv4.UsedIPs)

	// Change MinAllocate to 20
	withIPAMPreAllocate(0)(cn)
	withIPAMMinAllocate(20)(cn)

	mngr.Upsert(updateCiliumNode(cn, 20, 8))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 20, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 8, node.Stats().IPv4.UsedIPs)
}

// TestNodeManagerMinAllocateAndPreallocate tests MinAllocate in combination with PreAllocate
//
// - m3.large (3x ENIs, 2x10-2 IPs)
// - MinAllocate 10
// - MaxAllocate 0
// - PreAllocate 1
// - FirstInterfaceIndex 0
func TestNodeManagerMinAllocateAndPreallocate(t *testing.T) {
	setup(t)

	const instanceID = "i-testNodeManagerMinAllocateAndPreallocate-1"

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node2", withTestDefaults(), withInstanceID(instanceID), withInstanceType("m3.large"),
		withIPAMPreAllocate(1), withIPAMMinAllocate(10))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node := mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 9 out of 10 IPs, no additional IPs should be allocated
	mngr.Upsert(updateCiliumNode(cn, 10, 9))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))
	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 9, node.Stats().IPv4.UsedIPs)

	// Use 10 out of 10 IPs, PreAllocate 1 must kick in and allocate an additional IP
	mngr.Upsert(updateCiliumNode(cn, 10, 10))
	syncTime := instances.Resync(t.Context())
	mngr.Resync(t.Context(), syncTime)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))
	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 11, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 10, node.Stats().IPv4.UsedIPs)

	// Release some IPs, no additional IPs should be allocated
	mngr.Upsert(updateCiliumNode(cn, 10, 8))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))
	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 11, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 8, node.Stats().IPv4.UsedIPs)
}

// TestNodeManagerReleaseAddress tests PreAllocate, MinAllocate and MaxAboveWatermark
// when release excess IP is enabled
//
// - m4.xlarge (4x ENIs, 3x15-3 IPs)
// - MinAllocate 10
// - MaxAllocate 0
// - PreAllocate 2
// - MaxAboveWatermark 3
// - FirstInterfaceIndex 0
func TestNodeManagerReleaseAddress(t *testing.T) {
	setup(t)

	const instanceID = "i-testNodeManagerReleaseAddress-1"

	operatorOption.Config.ExcessIPReleaseDelay = 2
	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, true, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node3", withTestDefaults(), withInstanceID(instanceID), withInstanceType("m4.xlarge"),
		withIPAMPreAllocate(2), withIPAMMinAllocate(10), withIPAMMaxAboveWatermark(3))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))

	// 10 min-allocate + 3 max-above-watermark => 13 IPs must become
	// available as 13 < 14 (interface limit)
	node := mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 13, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 11 out of 13 IPs, no additional IPs should be allocated
	mngr.Upsert(updateCiliumNode(cn, 13, 11))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 13, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 11, node.Stats().IPv4.UsedIPs)

	// Use 13 out of 13 IPs, PreAllocate 2 + MaxAboveWatermark 3 must kick in
	// and allocate 5 additional IPs
	mngr.Upsert(updateCiliumNode(cn, 13, 13))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 18, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 13, node.Stats().IPv4.UsedIPs)

	// Reduce used IPs to 10, this leads to 8 excess IPs but release
	// occurs at interval based resync, so expect timeout at first
	mngr.Upsert(updateCiliumNode(cn, 18, 10))
	require.Error(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 2*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 18, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 10, node.Stats().IPv4.UsedIPs)

	// Trigger resync manually, excess IPs should be released
	// 10 used + 2 pre-allocate + 3 max-above-watermark => 15
	node = mngr.Get("node3")
	eniNode, castOK := node.Ops().(*Node)
	require.True(t, castOK)
	obj := node.ResourceCopy()
	eniNode.mutex.RLock()
	obj.Status.ENI.ENIs = eniNode.enis
	eniNode.mutex.RUnlock()
	node.UpdatedResource(obj)

	// Excess timestamps should be registered after this
	syncTime := instances.Resync(t.Context())
	mngr.Resync(t.Context(), syncTime)

	// Acknowledge release IPs after 3 secs
	time.AfterFunc(3*time.Second, func() {
		// Excess delay duration should have elapsed by now, trigger resync again.
		// IPs should be marked as excess
		syncTime := instances.Resync(t.Context())
		mngr.Resync(t.Context(), syncTime)
		time.Sleep(1 * time.Second)
		node.PopulateIPReleaseStatus(obj)
		// Fake acknowledge IPs for release like agent would.
		testipam.FakeAcknowledgeReleaseIps(obj)
		node.UpdatedResource(obj)
		// Resync one more time to process acknowledgements.
		syncTime = instances.Resync(t.Context())
		mngr.Resync(t.Context(), syncTime)
	})

	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 13, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 10, node.Stats().IPv4.UsedIPs)
}

// TestNodeManagerENIExcludeInterfaceTags tests ENI allocation with interface exclusion
//
// - m5.large (3x ENIs, 2x10-2 IPs)
// - MinAllocate 0
// - MaxAllocate 0
// - PreAllocate 8
// - FirstInterfaceIndex 0
// - ExcludeInterfaceTags {cilium.io/no_manage=true}
func TestNodeManagerENIExcludeInterfaceTags(t *testing.T) {
	setup(t)

	const instanceID = "i-testNodeManagerDefaultAllocation-0"

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	err = ec2api.TagENI(t.Context(), eniID1, map[string]string{
		"foo":                 "bar",
		"cilium.io/no_manage": "true",
	})
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node1", withTestDefaults(), withInstanceID(instanceID), withInstanceType("m5.large"),
		withExcludeInterfaceTags(map[string]string{"cilium.io/no_manage": "true"}), withIPAMPreAllocate(8))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 8, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Checks that we have created a new interface, and not allocated any IPs
	// to the existing one
	eniNode, castOK := node.Ops().(*Node)
	require.True(t, castOK)
	eniNode.mutex.RLock()
	require.Len(t, eniNode.enis, 2)
	require.Empty(t, eniNode.enis[eniID1].Addresses)
	require.Equal(t, "true", eniNode.enis[eniID1].Tags["cilium.io/no_manage"])
	eniNode.mutex.RUnlock()

	// Use 7 out of 8 IPs
	mngr.Upsert(updateCiliumNode(cn, 8, 7))
	mngr.Resync(t.Context(), instances.Resync(t.Context()))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node = mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 15, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 7, node.Stats().IPv4.UsedIPs)

	// Unmanaged ENI remains unmanaged
	eniNode.mutex.RLock()
	require.Len(t, eniNode.enis, 3)
	require.Empty(t, eniNode.enis[eniID1].Addresses)
	require.Equal(t, "true", eniNode.enis[eniID1].Tags["cilium.io/no_manage"])
	eniNode.mutex.RUnlock()
}

// TestNodeManagerExceedENICapacity tests exceeding ENI capacity
//
// - t2.xlarge (3x ENIs, 3x15-3 IPs)
// - MinAllocate 20
// - MaxAllocate 0
// - PreAllocate 8
// - FirstInterfaceIndex 0
func TestNodeManagerExceedENICapacity(t *testing.T) {
	setup(t)

	const instanceID = "i-testNodeManagerExceedENICapacity-1"

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node2", withTestDefaults(), withInstanceID(instanceID), withInstanceType("t2.xlarge"),
		withIPAMPreAllocate(8), withIPAMMinAllocate(20))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node := mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 20, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 40 out of 42 available IPs, we should reach 0 address needed once we
	// assigned the remaining 3 that the t2.xlarge instance type supports
	// (3x15 - 3 = 42 max)
	mngr.Upsert(updateCiliumNode(cn, 42, 40))
	syncTime := instances.Resync(t.Context())
	mngr.Resync(t.Context(), syncTime)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 42, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 40, node.Stats().IPv4.UsedIPs)
}

// TestInterfaceCreatedInInitialSubnet tests that additional ENIs are allocated in the same subnet
// as the first ENI, if possible.
//
// - t2.xlarge (3x ENIs, 3x15-3 IPs)
// - MinAllocate 0
// - MaxAllocate 0
// - PreAllocate 16
// - FirstInterfaceIndex 0
func TestInterfaceCreatedInInitialSubnet(t *testing.T) {
	setup(t)

	const instanceID = "i-testCreateInterfaceInCorrectSubnet-1"

	testSubnet2 := &ipamTypes.Subnet{
		ID:                 "s-2",
		AvailabilityZone:   "us-west-1",
		VirtualNetworkID:   "vpc-1",
		AvailableAddresses: 500, // more than s-1
		Tags:               ipamTypes.Tags{"k": "v"},
	}

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet, testSubnet2}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, testSubnet.ID, "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node1", withTestDefaults(), withInstanceID(instanceID), withInstanceType("t2.xlarge"),
		withIPAMPreAllocate(16), withNodeSubnetID(testSubnet.ID))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 16, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Checks that we have created a new interface and that we did so in the same subnet.
	eniNode, castOK := node.Ops().(*Node)
	require.True(t, castOK)
	eniNode.mutex.RLock()
	require.Len(t, eniNode.enis, 2)
	for _, eni := range eniNode.enis {
		require.Equal(t, testSubnet.ID, eni.Subnet.ID)
	}
	eniNode.mutex.RUnlock()
}

type nodeState struct {
	cn           *v2.CiliumNode
	name         string
	instanceName string
}

// TestNodeManagerManyNodes tests IP allocation of 100 nodes across 3 subnets
//
// - c3.xlarge (4x ENIs, 4x15-4 IPs)
// - MinAllocate 10
// - MaxAllocate 0
// - PreAllocate 1
// - FirstInterfaceIndex 1
func TestNodeManagerManyNodes(t *testing.T) {
	t.Skip("This test is flaky, see https://github.com/cilium/cilium/issues/11560")

	setup(t)

	const (
		numNodes    = 100
		minAllocate = 10
	)

	subnets := []*ipamTypes.Subnet{
		{ID: "mgmt-1", AvailabilityZone: "us-west-1", VirtualNetworkID: "vpc-1", AvailableAddresses: 100},
		{ID: "s-1", AvailabilityZone: "us-west-1", VirtualNetworkID: "vpc-1", AvailableAddresses: 400},
		{ID: "s-2", AvailabilityZone: "us-west-1", VirtualNetworkID: "vpc-1", AvailableAddresses: 400},
		{ID: "s-3", AvailabilityZone: "us-west-1", VirtualNetworkID: "vpc-1", AvailableAddresses: 400},
	}

	ec2api := ec2mock.NewAPI(subnets, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instancesManager, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instancesManager)
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instancesManager, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	state := make([]*nodeState, numNodes)

	for i := range state {
		eniID, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "mgmt-1", "desc", []string{"sg1", "sg2"}, false)
		require.NoError(t, err)
		_, err = ec2api.AttachNetworkInterface(t.Context(), 0, fmt.Sprintf("i-testNodeManagerManyNodes-%d", i), eniID)
		require.NoError(t, err)
		instancesManager.Resync(t.Context())
		s := &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("i-testNodeManagerManyNodes-%d", i)}
		s.cn = newCiliumNode(s.name, withTestDefaults(), withInstanceID(s.instanceName), withInstanceType("c3.xlarge"),
			withFirstInterfaceIndex(1), withIPAMPreAllocate(1), withIPAMMinAllocate(minAllocate))
		state[i] = s
		mngr.Upsert(s.cn)
	}

	for _, s := range state {
		require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, s.name, 0) }, 5*time.Second))

		node := mngr.Get(s.name)
		require.NotNil(t, node)
		if node.Stats().IPv4.AvailableIPs < minAllocate {
			t.Errorf("Node %s allocation shortage. expected at least: %d, allocated: %d", s.name, minAllocate, node.Stats().IPv4.AvailableIPs)
			t.Fail()
		}
		require.Equal(t, 0, node.Stats().IPv4.UsedIPs)
	}

	// The above check returns as soon as the address requirements are met.
	// The metrics may still be oudated, resync all nodes to update
	// metrics.
	mngr.Resync(t.Context(), time.Now())

	require.Equal(t, numNodes, metricsapi.Nodes("total"))
	require.Equal(t, 0, metricsapi.Nodes("in-deficit"))
	require.Equal(t, 0, metricsapi.Nodes("at-capacity"))

	if allocated := metricsapi.AllocatedIPs("available"); allocated < numNodes*minAllocate {
		t.Errorf("IP allocation shortage. expected at least: %d, allocated: %d", numNodes*minAllocate, allocated)
		t.Fail()
	}
	require.Equal(t, 0, metricsapi.AllocatedIPs("needed"))
	require.Equal(t, 0, metricsapi.AllocatedIPs("used"))

	// All subnets must have been used for allocation
	for _, subnet := range subnets {
		require.NotEqual(t, 0, metricsapi.GetAllocationAttempts("createInterfaceAndAllocateIP", "success", subnet.ID))
		require.Equal(t, 0, metricsapi.IPAllocations(subnet.ID))
	}

	require.NotEqual(t, 0, metricsapi.ResyncCount())
	require.NotEqual(t, 0, metricsapi.AvailableInterfaces())
}

// TestNodeManagerInstanceNotRunning verifies that allocation correctly detects
// instances which are no longer running
//
// - FirstInterfaceIndex 1
func TestNodeManagerInstanceNotRunning(t *testing.T) {
	setup(t)

	const instanceID = "i-testNodeManagerInstanceNotRunning-0"

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	metricsMock := metricsmock.NewMockMetrics()
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	ec2api.SetMockError(ec2mock.AttachNetworkInterface, errors.New("foo is not 'running' foo"))
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node, ENI attachement will fail
	cn := newCiliumNode("node1", withTestDefaults(), withInstanceID(instanceID), withInstanceType("m4.large"),
		withFirstInterfaceIndex(1), withIPAMPreAllocate(8))
	mngr.Upsert(cn)

	// Wait for node to be declared notRunning
	require.NoError(t, testutils.WaitUntil(func() bool {
		if n := mngr.Get("node1"); n != nil {
			return !n.IsRunning()
		}
		return false
	}, 5*time.Second))

	// Metric should not indicate failure
	require.Equal(t, int64(0), metricsMock.GetAllocationAttempts("createInterfaceAndAllocateIP", "unableToAttachENI", testSubnet.ID))

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 0, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)
}

// TestInstanceBeenDeleted verifies that instance deletion is correctly detected
// and no further action is taken
//
// - m4.large (2x ENIs, 2x10-2 IPs)
// - FirstInterfaceIndex 0
func TestInstanceBeenDeleted(t *testing.T) {
	setup(t)

	const instanceID = "i-testInstanceBeenDeleted-0"

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	eniID2, _, err := ec2api.CreateNetworkInterface(t.Context(), 8, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 1, instanceID, eniID2)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	cn := newCiliumNode("node1", withInstanceID(instanceID), withInstanceType("m4.large"), withIPAMPreAllocate(8))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 8, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Delete all enis attached to instance, this mocks the operation of
	// deleting the instance. The deletion should be detected.
	err = ec2api.DetachNetworkInterface(t.Context(), instanceID, eniID1)
	require.NoError(t, err)
	err = ec2api.DeleteNetworkInterface(t.Context(), eniID1)
	require.NoError(t, err)
	err = ec2api.DetachNetworkInterface(t.Context(), instanceID, eniID2)
	require.NoError(t, err)
	err = ec2api.DeleteNetworkInterface(t.Context(), eniID2)
	require.NoError(t, err)
	// Resync instances from mocked AWS
	instances.Resync(t.Context())
	// Use 2 out of 9 IPs
	mngr.Upsert(updateCiliumNode(cn, 9, 2))

	// Instance deletion detected, no allocation happened despite of the IP deficit.
	require.Equal(t, 8, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)
	require.Equal(t, 0, node.Stats().IPv4.NeededIPs)
	require.Equal(t, 0, node.Stats().IPv4.ExcessIPs)
}

// TestNodeManagerStaticIP tests allocation with a static IP
//
// - m5.large (3x ENIs, 2x10-2 IPs)
// - MinAllocate 0
// - MaxAllocate 0
// - PreAllocate 8
// - FirstInterfaceIndex 0
func TestNodeManagerStaticIP(t *testing.T) {
	setup(t)

	const instanceID = "i-testNodeManagerStaticIP-0"

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	staticIPTags := map[string]string{"some-eip-tag": "some-value"}
	cn := newCiliumNode("node1", withTestDefaults(), withInstanceID(instanceID), withInstanceType("m5.large"), withIPAMPreAllocate(8), withIPAMStaticIPTags(staticIPTags))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 8, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 1 IP
	mngr.Upsert(updateCiliumNode(cn, 8, 1))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node = mngr.Get("node1")
	require.NotNil(t, node)
	// Verify that the static IP has been successfully assigned
	require.Equal(t, "192.0.2.254", node.Stats().IPv4.AssignedStaticIP)
}

// TestNodeManagerStaticIPAlreadyAssociated verifies that when an ENI already has a public IP assigned to it, it is properly detected
//
// - m5.large (3x ENIs, 2x10-2 IPs)
// - MinAllocate 0
// - MaxAllocate 0
// - PreAllocate 8
// - FirstInterfaceIndex 0
func TestNodeManagerStaticIPAlreadyAssociated(t *testing.T) {
	setup(t)

	const instanceID = "i-testNodeManagerStaticIPAlreadyAssociated-0"

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(hivetest.Logger(t), ec2api)
	require.NoError(t, err)
	require.NotNil(t, instances)

	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	staticIP, err := ec2api.AssociateEIP(t.Context(), instanceID, make(ipamTypes.Tags))
	require.NoError(t, err)
	instances.Resync(t.Context())
	mngr, err := ipam.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	cn := newCiliumNode("node1", withTestDefaults(), withInstanceID(instanceID), withInstanceType("m5.large"), withIPAMPreAllocate(8))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 8, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)
	// Verify that the static IP which has already been assigned to the ENI has been successfully detected
	require.Equal(t, staticIP, node.Stats().IPv4.AssignedStaticIP)
}

func benchmarkAllocWorker(b *testing.B, workers int64, delay time.Duration, rateLimit float64, burst int) {
	testSubnet1 := &ipamTypes.Subnet{ID: "s-1", AvailabilityZone: "us-west-1", VirtualNetworkID: "vpc-1", AvailableAddresses: 1000000}
	testSubnet2 := &ipamTypes.Subnet{ID: "s-2", AvailabilityZone: "us-west-1", VirtualNetworkID: "vpc-1", AvailableAddresses: 1000000}
	testSubnet3 := &ipamTypes.Subnet{ID: "s-3", AvailabilityZone: "us-west-1", VirtualNetworkID: "vpc-1", AvailableAddresses: 1000000}

	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{testSubnet1, testSubnet2, testSubnet3}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, routeTables)
	ec2api.SetDelay(ec2mock.AllOperations, delay)
	ec2api.SetLimiter(rateLimit, burst)
	instances, err := NewInstancesManager(hivetest.Logger(b), ec2api)
	require.NoError(b, err)
	require.NotNil(b, instances)
	mngr, err := ipam.NewNodeManager(hivetest.Logger(b), instances, k8sapi, metricsapi, 10, false, false)
	require.NoError(b, err)
	require.NotNil(b, mngr)

	state := make([]*nodeState, b.N)

	b.ResetTimer()
	for i := range state {
		eniID, _, err := ec2api.CreateNetworkInterface(b.Context(), 0, "s-1", "desc", []string{"sg1", "sg2"}, false)
		require.NoError(b, err)
		_, err = ec2api.AttachNetworkInterface(b.Context(), 0, fmt.Sprintf("i-benchmarkAllocWorker-%d", i), eniID)
		require.NoError(b, err)
		instances.Resync(b.Context())
		s := &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("i-benchmarkAllocWorker-%d", i)}
		s.cn = newCiliumNode(s.name, withTestDefaults(), withInstanceID(s.instanceName), withInstanceType("m4.large"),
			withIPAMPreAllocate(1), withIPAMMinAllocate(10))
		state[i] = s
		mngr.Upsert(s.cn)
	}

restart:
	for _, s := range state {
		if !reachedAddressesNeeded(mngr, s.name, 0) {
			time.Sleep(5 * time.Millisecond)
			goto restart
		}
	}
	b.StopTimer()

}

func BenchmarkAllocDelay20Worker1(b *testing.B) {
	benchmarkAllocWorker(b, 1, 20*time.Millisecond, 100.0, 4)
}
func BenchmarkAllocDelay20Worker10(b *testing.B) {
	benchmarkAllocWorker(b, 10, 20*time.Millisecond, 100.0, 4)
}
func BenchmarkAllocDelay20Worker50(b *testing.B) {
	benchmarkAllocWorker(b, 50, 20*time.Millisecond, 100.0, 4)
}
func BenchmarkAllocDelay50Worker1(b *testing.B) {
	benchmarkAllocWorker(b, 1, 50*time.Millisecond, 100.0, 4)
}
func BenchmarkAllocDelay50Worker10(b *testing.B) {
	benchmarkAllocWorker(b, 10, 50*time.Millisecond, 100.0, 4)
}
func BenchmarkAllocDelay50Worker50(b *testing.B) {
	benchmarkAllocWorker(b, 50, 50*time.Millisecond, 100.0, 4)
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

func newCiliumNode(name string, opts ...func(*v2.CiliumNode)) *v2.CiliumNode {
	fii := 0
	cn := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: v2.NodeSpec{
			ENI: eniTypes.ENISpec{
				FirstInterfaceIndex: &fii,
				SecurityGroupTags:   map[string]string{},
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

	for _, opt := range opts {
		opt(cn)
	}

	return cn
}

func withTestDefaults() func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.ENI.AvailabilityZone = testSubnet.AvailabilityZone
		cn.Spec.ENI.VpcID = testVpc.ID
	}
}

func withInstanceID(instanceID string) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.InstanceID = instanceID
	}
}

func withInstanceType(instanceType string) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.ENI.InstanceType = instanceType
	}
}

func withFirstInterfaceIndex(firstInterface int) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.ENI.FirstInterfaceIndex = &firstInterface
	}
}

func withNodeSubnetID(id string) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.ENI.NodeSubnetID = id
	}
}

func withSecurityGroupTags(tags map[string]string) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.ENI.SecurityGroupTags = tags
	}
}

func withIPAMPreAllocate(preAlloc int) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.IPAM.PreAllocate = preAlloc
	}
}

func withIPAMMinAllocate(minAlloc int) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.IPAM.MinAllocate = minAlloc
	}
}

func withIPAMMaxAboveWatermark(aboveWM int) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.IPAM.MaxAboveWatermark = aboveWM
	}
}

func withIPAMStaticIPTags(tags map[string]string) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.IPAM.StaticIPTags = tags
	}
}

func withExcludeInterfaceTags(tags map[string]string) func(*v2.CiliumNode) {
	return func(cn *v2.CiliumNode) {
		cn.Spec.ENI.ExcludeInterfaceTags = tags
	}
}

func updateCiliumNode(cn *v2.CiliumNode, available, used int) *v2.CiliumNode {
	cn.Spec.IPAM.Pool = ipamTypes.AllocationMap{}
	for i := range used {
		cn.Spec.IPAM.Pool[fmt.Sprintf("1.1.1.%d", i)] = ipamTypes.AllocationIP{Resource: "foo"}
	}

	cn.Status.IPAM.Used = ipamTypes.AllocationMap{}
	for ip, ipAllocation := range cn.Spec.IPAM.Pool {
		if used > 0 {
			delete(cn.Spec.IPAM.Pool, ip)
			cn.Status.IPAM.Used[ip] = ipAllocation
			used--
		}
	}

	return cn
}

func reachedAddressesNeeded(mngr *ipam.NodeManager, nodeName string, needed int) (success bool) {
	if node := mngr.Get(nodeName); node != nil {
		success = node.GetNeededAddresses() == needed
	}
	return
}
