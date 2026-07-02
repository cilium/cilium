// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	ec2mock "github.com/cilium/cilium/pkg/aws/api/mock"
	metadataMock "github.com/cilium/cilium/pkg/aws/metadata/mock"
	eniTypes "github.com/cilium/cilium/pkg/aws/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/testutils"
)

// fakeOpsNode lets us drive Node.CreateInterface in a unit test. The default
// mockIPAMNode.Ops() panics, but CreateInterface calls n.node.Ops().IsPrefixDelegated(),
// so we return the Node itself as its own NodeOperations.
type fakeOpsNode struct {
	mockIPAMNode
	ops nodemanager.NodeOperations
}

func (f *fakeOpsNode) Ops() nodemanager.NodeOperations { return f.ops }

// TestPrefixFallbackFallsBackToSameSubnetWhenNoSiblingAvailable documents the
// correct behavior when a prefix delegated ENI cannot get a /28 in the selected
// subnet AND no eligible sibling subnet exists: the operator correctly falls back
// to /32 in the same subnet. This is acceptable — cross-subnet retry only helps
// when a sibling subnet with /28 capacity is available.
func TestPrefixFallbackFallsBackToSameSubnetWhenNoSiblingAvailable(t *testing.T) {
	const subnetID = "subnet-frag"

	// Mock a FRAGMENTED subnet: it has plenty of free /32 addresses (1000, far
	// more than one /28 of 16), but no free contiguous /28 prefix block. This is
	// the real-world fragmentation case from the report: AvailableIpAddressCount
	// stays high, yet the prefix create fails with the AWS subnet full error that
	// isSubnetAtPrefixCapacity matches. SetSubnetAtPrefixCapacity below models the
	// missing /28 capacity independently of the /32 count.
	mockSubnet := &ipamTypes.Subnet{
		ID:                 subnetID,
		VirtualNetworkID:   "vpc-1",
		AvailabilityZone:   "eu-west-1a",
		AvailableAddresses: 1000,
	}
	api := ec2mock.NewAPI(
		[]*ipamTypes.Subnet{mockSubnet},
		[]*ipamTypes.VirtualNetwork{{ID: "vpc-1"}},
		nil,
		nil,
	)
	// The subnet is fragmented: no free /28 block, so prefix allocation fails
	// while /32 allocation still succeeds.
	api.SetSubnetAtPrefixCapacity(subnetID, true)
	metaMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(context.Background(), hivetest.Logger(t), api, metaMock)
	require.NoError(t, err)

	// findSuitableSubnet reads the manager subnet cache directly.
	instances.subnets = map[string]*ipamTypes.Subnet{
		subnetID: {
			ID:                 subnetID,
			VirtualNetworkID:   "vpc-1",
			AvailabilityZone:   "eu-west-1a",
			AvailableAddresses: 1000,
		},
	}

	k8sObj := newCiliumNode("node1", withInstanceType("m5.large"))
	k8sObj.Spec.ENI.VpcID = "vpc-1"
	k8sObj.Spec.ENI.AvailabilityZone = "eu-west-1a"
	k8sObj.Spec.ENI.SubnetIDs = []string{subnetID}
	k8sObj.Spec.ENI.SecurityGroups = []string{"sg-1"}

	fake := &fakeOpsNode{mockIPAMNode: mockIPAMNode{instanceID: "i-123", prefixDelegation: true}}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     k8sObj,
		node:       fake,
		enis:       map[string]eniTypes.ENI{},
	}
	n.logger.Store(n.rootLogger)
	fake.ops = n // Node is its own NodeOperations

	require.True(t, n.IsPrefixDelegated(), "node should start prefix delegated")

	alloc := &nodemanager.AllocationAction{}
	alloc.IPv4.MaxIPsToAllocate = 2

	toAllocate, _, err := n.CreateInterface(context.Background(), alloc, hivetest.Logger(t))
	require.NoError(t, err)
	require.Equal(t, 2, toAllocate)

	// The ENI was created in the same subnet that could not fit a prefix.
	require.Equal(t, ipamTypes.PoolID(subnetID), alloc.PoolID)

	// Proof it used the /32 fallback and not a prefix: the mock subnet dropped by
	// exactly primary + 2 secondary = 3 addresses (1000 -> 997). A successful
	// prefix would have consumed a /28 block (16 addresses) instead. The subnet
	// kept hundreds of free /32 addresses throughout, so the fallback was driven
	// by missing /28 capacity (fragmentation), not by a nearly full subnet.
	subnetsAfter, err := api.GetSubnets(context.Background(), "vpc-1")
	require.NoError(t, err)
	require.Equal(t, 997, subnetsAfter[subnetID].AvailableAddresses)
}

// TestNoPrefixENIDisablesNodeAndDoesNotRecover proves root cause 3: a single
// ENI with secondary IPs and no prefixes disables prefix delegation for the
// whole node, adding more prefix capable ENIs does not undo it, and the node
// only recovers if that ENI drains down to its primary IP.
func TestNoPrefixENIDisablesNodeAndDoesNotRecover(t *testing.T) {
	api := ec2mock.NewAPI(nil, nil, nil, nil)
	metaMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(context.Background(), hivetest.Logger(t), api, metaMock)
	require.NoError(t, err)

	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     newCiliumNode("node1", withInstanceType("m5.large")),
		node:       &mockIPAMNode{instanceID: "i-123", prefixDelegation: true},
		enis:       map[string]eniTypes.ENI{},
	}
	n.logger.Store(n.rootLogger)

	// 1. One prefix delegated ENI: node is prefix delegated.
	n.enis["eni-pd"] = eniTypes.ENI{
		ID:        "eni-pd",
		IP:        iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
		Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.16")), iputil.AddrFrom(netip.MustParseAddr("10.0.0.17"))},
		Prefixes:  []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28"))},
	}
	require.True(t, n.IsPrefixDelegated(), "single prefix ENI should be delegated")

	// 2. Add a no prefix ENI with 2 secondary IPs (the /32 fallback result).
	n.enis["eni-32"] = eniTypes.ENI{
		ID:        "eni-32",
		IP:        iputil.AddrFrom(netip.MustParseAddr("10.0.1.4")),
		Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.1.4")), iputil.AddrFrom(netip.MustParseAddr("10.0.1.5")), iputil.AddrFrom(netip.MustParseAddr("10.0.1.6"))},
		Prefixes:  nil,
	}
	require.False(t, n.IsPrefixDelegated(), "one no-prefix ENI must disable the whole node")

	// 3. Adding another prefix capable ENI does NOT recover the node.
	n.enis["eni-pd2"] = eniTypes.ENI{
		ID:        "eni-pd2",
		IP:        iputil.AddrFrom(netip.MustParseAddr("10.0.2.4")),
		Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.2.16"))},
		Prefixes:  []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.2.16/28"))},
	}
	require.False(t, n.IsPrefixDelegated(), "extra prefix ENIs do not undo the disable")

	// 4. Draining the no prefix ENI down to its primary IP recovers the node.
	n.enis["eni-32"] = eniTypes.ENI{
		ID:        "eni-32",
		IP:        iputil.AddrFrom(netip.MustParseAddr("10.0.1.4")),
		Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.1.4"))}, // primary only, Addresses[0] == IP
		Prefixes:  nil,
	}
	require.True(t, n.IsPrefixDelegated(), "node recovers only when the no-prefix ENI drains to primary")
}

// TestPrefixFallbackTriesSiblingTaggedSubnet validates that when prefix ENI
// creation fails with InsufficientCidrBlocks in the selected subnet, CreateInterface
// retries prefix creation in other eligible same-AZ subnets before falling back
// to /32. With eni.subnet-tags-filter set and a healthy sibling subnet available,
// the retry succeeds and the ENI is created with a /28 prefix in the sibling subnet.
func TestPrefixFallbackTriesSiblingTaggedSubnet(t *testing.T) {
	const (
		fragSubnetID    = "subnet-frag"
		healthySubnetID = "subnet-healthy"
	)
	filterTags := ipamTypes.Tags{"kubernetes.io/role/cni": "1"}

	fragSubnet := &ipamTypes.Subnet{
		ID:                 fragSubnetID,
		VirtualNetworkID:   "vpc-1",
		AvailabilityZone:   "eu-west-1a",
		AvailableAddresses: 1000,
		Tags:               filterTags,
	}
	healthySubnet := &ipamTypes.Subnet{
		ID:                 healthySubnetID,
		VirtualNetworkID:   "vpc-1",
		AvailabilityZone:   "eu-west-1a",
		AvailableAddresses: 500,
		Tags:               filterTags,
	}
	api := ec2mock.NewAPI(
		[]*ipamTypes.Subnet{fragSubnet, healthySubnet},
		[]*ipamTypes.VirtualNetwork{{ID: "vpc-1"}},
		nil,
		nil,
	)
	// Only subnet-frag is fragmented. subnet-healthy has full /28 capacity.
	api.SetSubnetAtPrefixCapacity(fragSubnetID, true)

	metaMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(context.Background(), hivetest.Logger(t), api, metaMock)
	require.NoError(t, err)
	instances.subnets = map[string]*ipamTypes.Subnet{
		fragSubnetID:    fragSubnet.DeepCopy(),
		healthySubnetID: healthySubnet.DeepCopy(),
	}

	k8sObj := newCiliumNode("node1", withInstanceType("m5.large"))
	k8sObj.Spec.ENI.VpcID = "vpc-1"
	k8sObj.Spec.ENI.AvailabilityZone = "eu-west-1a"
	k8sObj.Spec.ENI.SubnetTags = filterTags
	k8sObj.Spec.ENI.SecurityGroups = []string{"sg-1"}

	fake := &fakeOpsNode{mockIPAMNode: mockIPAMNode{instanceID: "i-123", prefixDelegation: true}}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     k8sObj,
		node:       fake,
		enis:       map[string]eniTypes.ENI{},
	}
	n.logger.Store(n.rootLogger)
	fake.ops = n

	require.True(t, n.IsPrefixDelegated(), "node should start prefix delegated")

	alloc := &nodemanager.AllocationAction{}
	alloc.IPv4.MaxIPsToAllocate = 2

	toAllocate, _, err := n.CreateInterface(context.Background(), alloc, hivetest.Logger(t))
	require.NoError(t, err)
	require.Equal(t, 2, toAllocate)

	// The retry found the healthy sibling and created the ENI there with a prefix.
	require.Equal(t, ipamTypes.PoolID(healthySubnetID), alloc.PoolID,
		"cross-subnet retry must land the ENI in the healthy sibling subnet")

	subnetsAfter, err := api.GetSubnets(context.Background(), "vpc-1")
	require.NoError(t, err)
	// subnet-frag is untouched: the retry moved past it.
	require.Equal(t, 1000, subnetsAfter[fragSubnetID].AvailableAddresses,
		"fragmented subnet must be untouched after cross-subnet retry")
	// subnet-healthy consumed toAllocate+1 (primary+secondaries) + /28 = 19 (500 -> 481).
	require.Equal(t, 481, subnetsAfter[healthySubnetID].AvailableAddresses,
		"healthy subnet must show prefix allocation (2 secondary + primary + /28 = 19 addresses)")
	// Node stays prefix delegated: no /32-only ENI was created.
	require.True(t, n.IsPrefixDelegated(), "node must remain prefix delegated after successful cross-subnet retry")
}

// TestMultipleFallbackENIsUseHealthySiblingAndNodeStaysDelegated validates that
// repeated ENI creations in a fragmented subnet
// scenario correctly retry and land in the healthy sibling with prefix delegation,
// and the node never enters degraded /32 mode.
func TestMultipleFallbackENIsUseHealthySiblingAndNodeStaysDelegated(t *testing.T) {
	const (
		fragSubnetID    = "subnet-frag"
		healthySubnetID = "subnet-healthy"
	)
	filterTags := ipamTypes.Tags{"kubernetes.io/role/cni": "1"}
	fragSubnet := &ipamTypes.Subnet{ID: fragSubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 1000, Tags: filterTags}
	healthySubnet := &ipamTypes.Subnet{ID: healthySubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 500, Tags: filterTags}
	api := ec2mock.NewAPI(
		[]*ipamTypes.Subnet{fragSubnet, healthySubnet},
		[]*ipamTypes.VirtualNetwork{{ID: "vpc-1"}},
		nil,
		nil,
	)
	api.SetSubnetAtPrefixCapacity(fragSubnetID, true)
	metaMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(context.Background(), hivetest.Logger(t), api, metaMock)
	require.NoError(t, err)
	instances.subnets = map[string]*ipamTypes.Subnet{
		fragSubnetID:    fragSubnet.DeepCopy(),
		healthySubnetID: healthySubnet.DeepCopy(),
	}

	k8sObj := newCiliumNode("node1", withInstanceType("m5.large"))
	k8sObj.Spec.ENI.VpcID = "vpc-1"
	k8sObj.Spec.ENI.AvailabilityZone = "eu-west-1a"
	k8sObj.Spec.ENI.SubnetTags = filterTags
	k8sObj.Spec.ENI.SecurityGroups = []string{"sg-1"}

	fake := &fakeOpsNode{mockIPAMNode: mockIPAMNode{instanceID: "i-123", prefixDelegation: true}}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     k8sObj,
		node:       fake,
		enis:       map[string]eniTypes.ENI{},
	}
	n.logger.Store(n.rootLogger)
	fake.ops = n

	require.True(t, n.IsPrefixDelegated(), "node starts prefix delegated")

	eniKeys := []string{"eni-0", "eni-1", "eni-2"}
	for i := range 3 {
		alloc := &nodemanager.AllocationAction{}
		alloc.IPv4.MaxIPsToAllocate = 2
		_, _, err := n.CreateInterface(context.Background(), alloc, hivetest.Logger(t))
		require.NoError(t, err)
		// Every ENI lands in the healthy sibling via cross-subnet retry.
		require.Equal(t, ipamTypes.PoolID(healthySubnetID), alloc.PoolID,
			"cross-subnet retry must land the ENI in the healthy subnet")
		// Model the resync: ENI has a prefix so node stays delegated.
		n.enis[eniKeys[i]] = eniTypes.ENI{
			ID:       eniKeys[i],
			IP:       iputil.AddrFrom(netip.MustParseAddr("10.9.0.1")),
			Prefixes: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.9.0.0/28"))},
			Subnet:   eniTypes.AwsSubnet{ID: healthySubnetID},
		}
		// Node stays prefix delegated: no /32-only ENI was produced.
		require.True(t, n.IsPrefixDelegated(), "node must stay prefix delegated after cross-subnet retry")
	}

	subnetsAfter, err := api.GetSubnets(context.Background(), "vpc-1")
	require.NoError(t, err)
	// Fragmented subnet untouched across all three ENIs.
	require.Equal(t, 1000, subnetsAfter[fragSubnetID].AvailableAddresses,
		"fragmented subnet must be untouched")
	// Healthy subnet consumed toAllocate+1 + /28 = 19 per ENI, 3 ENIs = 57 (500 -> 443).
	require.Equal(t, 443, subnetsAfter[healthySubnetID].AvailableAddresses,
		"healthy subnet consumed by prefix ENIs (19 each: 2 secondary + primary + /28)")
}

// TestDegradedNodeKeepsAllocatingSlash32InHealthySubnet captures the reporter's
// exact numbers (fragmented subnet reports far fewer addresses than the healthy
// sibling) and the precise, honest behavior: once the node is degraded, new ENIs
// are NOT stuck on the fragmented subnet. findSuitableSubnet re-evaluates and
// picks the healthy subnet because it reports more free addresses. But because
// IsPrefixDelegated is false node wide, every new ENI is still created in /32
// mode, so prefix delegation is never re-enabled even though the healthy subnet
// has abundant free /28 capacity. The node is stuck in /32 mode, not stuck on a
// single subnet, and the healthy subnet gets consumed with /32 ENIs.
func TestDegradedNodeKeepsAllocatingSlash32InHealthySubnet(t *testing.T) {
	const (
		fragSubnetID    = "subnet-frag"
		healthySubnetID = "subnet-healthy"
	)
	filterTags := ipamTypes.Tags{"kubernetes.io/role/cni": "1"}
	// Accurate cache, reporter's numbers.
	fragSubnet := &ipamTypes.Subnet{ID: fragSubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 100, Tags: filterTags}
	healthySubnet := &ipamTypes.Subnet{ID: healthySubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 2000, Tags: filterTags}
	api := ec2mock.NewAPI(
		[]*ipamTypes.Subnet{fragSubnet, healthySubnet},
		[]*ipamTypes.VirtualNetwork{{ID: "vpc-1"}},
		nil,
		nil,
	)
	api.SetSubnetAtPrefixCapacity(fragSubnetID, true)
	metaMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(context.Background(), hivetest.Logger(t), api, metaMock)
	require.NoError(t, err)
	instances.subnets = map[string]*ipamTypes.Subnet{
		fragSubnetID:    fragSubnet.DeepCopy(),
		healthySubnetID: healthySubnet.DeepCopy(),
	}

	k8sObj := newCiliumNode("node1", withInstanceType("m5.large"))
	k8sObj.Spec.ENI.VpcID = "vpc-1"
	k8sObj.Spec.ENI.AvailabilityZone = "eu-west-1a"
	k8sObj.Spec.ENI.SubnetTags = filterTags
	k8sObj.Spec.ENI.SecurityGroups = []string{"sg-1"}

	fake := &fakeOpsNode{mockIPAMNode: mockIPAMNode{instanceID: "i-123", prefixDelegation: true}}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     k8sObj,
		node:       fake,
		enis:       map[string]eniTypes.ENI{},
	}
	n.logger.Store(n.rootLogger)
	fake.ops = n

	// Node already degraded: one no-prefix ENI pinned to the fragmented subnet
	// (the primary ENI that AWS placed there at instance launch).
	n.enis["primary-x"] = eniTypes.ENI{
		ID:        "primary-x",
		IP:        iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
		Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")), iputil.AddrFrom(netip.MustParseAddr("10.0.0.5"))},
		Prefixes:  nil,
		Subnet:    eniTypes.AwsSubnet{ID: fragSubnetID},
	}
	require.False(t, n.IsPrefixDelegated(), "node is already degraded")

	for range 3 {
		alloc := &nodemanager.AllocationAction{}
		alloc.IPv4.MaxIPsToAllocate = 2
		_, _, err := n.CreateInterface(context.Background(), alloc, hivetest.Logger(t))
		require.NoError(t, err)
		// Re-evaluation picks the higher-availability subnet, so the ENI is NOT
		// stuck on the fragmented subnet.
		require.Equal(t, ipamTypes.PoolID(healthySubnetID), alloc.PoolID, "new ENI placed in the higher-availability subnet")
		require.False(t, n.IsPrefixDelegated(), "node stays disabled")
	}

	subnetsAfter, err := api.GetSubnets(context.Background(), "vpc-1")
	require.NoError(t, err)
	// Every ENI is created in /32 mode: primary + 2 secondary = 3 per ENI, 3 ENIs
	// = 9 (2000 -> 1991). A successful /28 would have consumed ~16 per ENI, so the
	// drop of 9 proves no prefixes were allocated despite the subnet having /28
	// capacity. Prefix delegation is never re-enabled node wide.
	require.Equal(t, 1991, subnetsAfter[healthySubnetID].AvailableAddresses, "healthy subnet consumed by /32 ENIs (3 each), proving no prefixes were allocated")
	require.Equal(t, 100, subnetsAfter[fragSubnetID].AvailableAddresses, "fragmented subnet untouched")
}

// TestNodeSubnetPreferenceFallsBackToSiblingOnPrefixFailure validates that when
// the node subnet (NodeSubnetID path) is fragmented, the cross-subnet retry finds
// a healthy sibling and creates the ENI there with a prefix instead of falling
// back to /32 in the node subnet.
func TestNodeSubnetPreferenceFallsBackToSiblingOnPrefixFailure(t *testing.T) {
	const (
		nodeSubnetID    = "subnet-x"
		healthySubnetID = "subnet-y"
	)
	x := &ipamTypes.Subnet{ID: nodeSubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 15}
	y := &ipamTypes.Subnet{ID: healthySubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 2000}
	api := ec2mock.NewAPI(
		[]*ipamTypes.Subnet{x, y},
		[]*ipamTypes.VirtualNetwork{{ID: "vpc-1"}},
		nil,
		nil,
	)
	api.SetSubnetAtPrefixCapacity(nodeSubnetID, true)
	metaMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(context.Background(), hivetest.Logger(t), api, metaMock)
	require.NoError(t, err)
	instances.subnets = map[string]*ipamTypes.Subnet{
		nodeSubnetID:    x.DeepCopy(),
		healthySubnetID: y.DeepCopy(),
	}

	k8sObj := newCiliumNode("node1", withInstanceType("m5.large"))
	k8sObj.Spec.ENI.VpcID = "vpc-1"
	k8sObj.Spec.ENI.AvailabilityZone = "eu-west-1a"
	k8sObj.Spec.ENI.NodeSubnetID = nodeSubnetID
	k8sObj.Spec.ENI.SecurityGroups = []string{"sg-1"}

	fake := &fakeOpsNode{mockIPAMNode: mockIPAMNode{instanceID: "i-123", prefixDelegation: true}}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     k8sObj,
		node:       fake,
		enis:       map[string]eniTypes.ENI{},
	}
	n.logger.Store(n.rootLogger)
	fake.ops = n

	require.True(t, n.IsPrefixDelegated(), "node should start prefix delegated")

	alloc := &nodemanager.AllocationAction{}
	alloc.IPv4.MaxIPsToAllocate = 2
	_, _, err = n.CreateInterface(context.Background(), alloc, hivetest.Logger(t))
	require.NoError(t, err)

	// The cross-subnet retry found the healthy sibling.
	require.Equal(t, ipamTypes.PoolID(healthySubnetID), alloc.PoolID,
		"cross-subnet retry must land the ENI in the healthy sibling subnet")

	subnetsAfter, err := api.GetSubnets(context.Background(), "vpc-1")
	require.NoError(t, err)
	// Node subnet untouched: /32 fallback never ran there.
	require.Equal(t, 15, subnetsAfter[nodeSubnetID].AvailableAddresses,
		"node subnet must be untouched after cross-subnet retry")
	// Healthy subnet consumed toAllocate+1 + /28 = 19 (2000 -> 1981).
	require.Equal(t, 1981, subnetsAfter[healthySubnetID].AvailableAddresses,
		"healthy sibling consumed by prefix allocation")
	// Node stays delegated.
	require.True(t, n.IsPrefixDelegated(), "node must remain prefix delegated")
}

// TestPrepareIPAllocationPrefersExistingENIInNodeSubnet answers the reporter's
// first question: "will Cilium use the ENI the node already has, even when a /28
// can no longer be attached?" Yes. PrepareIPAllocation iterates only the node's
// existing ENIs and selects the first one that still has room and whose subnet
// reports any free address. It never considers a subnet that has no ENI on the
// node. So the existing ENI pinned to the fragmented node subnet is selected for
// top-up before any new ENI or any other subnet is even looked at. AllocateIPs
// then tops it up (see TestAllocateIPsFallsBackToSlash32OnExistingENIInSameSubnet).
func TestPrepareIPAllocationPrefersExistingENIInNodeSubnet(t *testing.T) {
	const (
		nodeSubnetID    = "subnet-x"
		healthySubnetID = "subnet-y"
	)
	x := &ipamTypes.Subnet{ID: nodeSubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 15}
	y := &ipamTypes.Subnet{ID: healthySubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 2000}
	api := ec2mock.NewAPI(
		[]*ipamTypes.Subnet{x, y},
		[]*ipamTypes.VirtualNetwork{{ID: "vpc-1"}},
		nil,
		nil,
	)
	api.SetSubnetAtPrefixCapacity(nodeSubnetID, true)
	metaMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(context.Background(), hivetest.Logger(t), api, metaMock)
	require.NoError(t, err)
	instances.subnets = map[string]*ipamTypes.Subnet{
		nodeSubnetID:    x.DeepCopy(),
		healthySubnetID: y.DeepCopy(),
	}

	k8sObj := newCiliumNode("node1", withInstanceType("m5.large"))
	k8sObj.Spec.ENI.VpcID = "vpc-1"
	k8sObj.Spec.ENI.AvailabilityZone = "eu-west-1a"
	k8sObj.Spec.ENI.NodeSubnetID = nodeSubnetID

	fake := &fakeOpsNode{mockIPAMNode: mockIPAMNode{instanceID: "i-123", prefixDelegation: true}}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     k8sObj,
		node:       fake,
		enis:       map[string]eniTypes.ENI{},
	}
	n.logger.Store(n.rootLogger)
	fake.ops = n

	// The node's existing prefix-delegated primary ENI in subnet-x, with room.
	n.enis["eni-primary"] = eniTypes.ENI{
		ID:        "eni-primary",
		IP:        iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
		Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.16"))},
		Prefixes:  []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28"))},
		Subnet:    eniTypes.AwsSubnet{ID: nodeSubnetID},
		Number:    0,
	}
	require.True(t, n.IsPrefixDelegated(), "node should be prefix delegated")

	a, err := n.PrepareIPAllocation(hivetest.Logger(t))
	require.NoError(t, err)
	// The existing ENI in the node subnet is chosen for top-up.
	require.Equal(t, "eni-primary", a.InterfaceID, "existing ENI in the node subnet is selected")
	require.Equal(t, ipamTypes.PoolID(nodeSubnetID), a.PoolID, "top-up targets the node subnet, not the healthy sibling")
	require.Equal(t, 1, a.IPv4.InterfaceCandidates, "only the node's own ENI is a candidate")
	require.Positive(t, a.IPv4.AvailableForAllocation, "the existing ENI is topped up rather than creating a new ENI")
}

// TestAllocateIPsFallsBackToSlash32OnExistingENIInSameSubnet reproduces the
// "Resolving IP deficit ... selectedInterface=eni-... selectedPoolID=subnet-X"
// path: once an existing ENI in the fragmented subnet is selected, AllocateIPs
// tries to add a /28 prefix to it, AssignENIPrefixes fails with the AWS subnet
// full error, and it falls back to AssignPrivateIpAddresses (/32) on that SAME
// ENI in the SAME subnet. There is no subnet selection in this path at all, so
// the healthy sibling subnet is irrelevant: the existing ENI is pinned to the
// fragmented subnet and that is where the /32 addresses are added.
func TestAllocateIPsFallsBackToSlash32OnExistingENIInSameSubnet(t *testing.T) {
	const (
		nodeSubnetID    = "subnet-x"
		healthySubnetID = "subnet-y"
	)
	x := &ipamTypes.Subnet{ID: nodeSubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 15}
	y := &ipamTypes.Subnet{ID: healthySubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 2000}
	api := ec2mock.NewAPI(
		[]*ipamTypes.Subnet{x, y},
		[]*ipamTypes.VirtualNetwork{{ID: "vpc-1"}},
		nil,
		nil,
	)
	api.SetSubnetAtPrefixCapacity(nodeSubnetID, true)
	metaMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(context.Background(), hivetest.Logger(t), api, metaMock)
	require.NoError(t, err)
	instances.subnets = map[string]*ipamTypes.Subnet{
		nodeSubnetID:    x.DeepCopy(),
		healthySubnetID: y.DeepCopy(),
	}

	k8sObj := newCiliumNode("node1", withInstanceType("m5.large"))
	k8sObj.Spec.ENI.VpcID = "vpc-1"
	k8sObj.Spec.ENI.AvailabilityZone = "eu-west-1a"
	k8sObj.Spec.ENI.NodeSubnetID = nodeSubnetID
	k8sObj.Spec.ENI.SecurityGroups = []string{"sg-1"}

	fake := &fakeOpsNode{mockIPAMNode: mockIPAMNode{instanceID: "i-123", prefixDelegation: true}}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     k8sObj,
		node:       fake,
		enis:       map[string]eniTypes.ENI{},
	}
	n.logger.Store(n.rootLogger)
	fake.ops = n

	// Register an existing ENI in subnet-x with the mock (prefixes off so the
	// create succeeds) and mirror it into the node view as prefix-delegated-capable.
	eniID, _, err := api.CreateNetworkInterface(context.Background(), 0, nodeSubnetID, "desc", []string{"sg-1"}, false, false)
	require.NoError(t, err)
	_, err = api.AttachNetworkInterface(context.Background(), 0, "i-123", eniID)
	require.NoError(t, err)
	n.enis[eniID] = eniTypes.ENI{
		ID:        eniID,
		IP:        iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
		Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.4"))},
		Prefixes:  nil,
		Subnet:    eniTypes.AwsSubnet{ID: nodeSubnetID},
	}
	require.True(t, n.IsPrefixDelegated(), "node should be prefix delegated")

	subnetsBefore, err := api.GetSubnets(context.Background(), "vpc-1")
	require.NoError(t, err)
	xBefore := subnetsBefore[nodeSubnetID].AvailableAddresses

	a := &nodemanager.AllocationAction{InterfaceID: eniID}
	a.PoolID = ipamTypes.PoolID(nodeSubnetID)
	a.IPv4.AvailableForAllocation = 2
	err = n.AllocateIPs(context.Background(), a)
	require.NoError(t, err, "AllocateIPs falls back to /32 and succeeds on the existing ENI")

	subnetsAfter, err := api.GetSubnets(context.Background(), "vpc-1")
	require.NoError(t, err)
	// The two /32 addresses were taken from subnet-x (the existing ENI's subnet),
	// proving the prefix create failed and the /32 fallback ran in the same subnet.
	require.Equal(t, xBefore-2, subnetsAfter[nodeSubnetID].AvailableAddresses, "the /32 fallback consumed 2 addresses in the node subnet")
	// The healthy sibling subnet is untouched: AllocateIPs never does subnet selection.
	require.Equal(t, 2000, subnetsAfter[healthySubnetID].AvailableAddresses, "healthy sibling subnet untouched")
}

// TestAllocateIPsProducesMixedPrefixAndSlash32ENI addresses the field observation
// that mixed ENIs (a single ENI carrying both /28 prefixes and individual /32
// secondary IPs) are never seen on real nodes. The question it answers is
// whether Cilium has a hard guard against producing one. It does NOT.
//
// AWS allows an ENI to hold both prefixes and individual secondary IPs at once
// (each secondary IP costs one prefix slot, per the EKS prefix-mode docs), and
// nothing in AllocateIPs, PrepareIPAllocation, or the IPAM handleIPAllocation
// loop prevents it. This test gives an existing ENI a real /28 prefix while its
// subnet is healthy, then fragments the subnet (no free /28 left) and drives
// AllocateIPs on that same ENI while the node is still prefix delegated. The
// prefix top-up (AssignENIPrefixes) fails, the /32 fallback (AssignPrivateIp
// Addresses) succeeds on the SAME ENI, and the ENI ends up MIXED: it keeps its
// prefix and gains 2 individual /32 addresses.
//
// So the reason mixed ENIs are not observed in practice is allocation ordering,
// not a code guard: in the field, fragmentation usually bites the NEW-ENI path
// (CreateInterface), which produces a zero-prefix /32-only ENI and immediately
// disables prefix delegation node wide (IsPrefixDelegated requires zero prefixes
// on an ENI to trip). Once disabled, Cilium issues no further prefix requests,
// so the steady state is prefix-only ENIs plus /32-only ENIs, never mixed. The
// reporter's own warning line (from CreateInterface, addresses=2,
// isPrefixDelegated=true) confirms the new-ENI path was the trigger. This test
// proves the mixed state is nonetheless reachable through the top-up path.
func TestAllocateIPsProducesMixedPrefixAndSlash32ENI(t *testing.T) {
	const nodeSubnetID = "subnet-x"
	x := &ipamTypes.Subnet{ID: nodeSubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 1000}
	api := ec2mock.NewAPI(
		[]*ipamTypes.Subnet{x},
		[]*ipamTypes.VirtualNetwork{{ID: "vpc-1"}},
		nil,
		nil,
	)
	metaMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(context.Background(), hivetest.Logger(t), api, metaMock)
	require.NoError(t, err)
	instances.subnets = map[string]*ipamTypes.Subnet{nodeSubnetID: x.DeepCopy()}

	k8sObj := newCiliumNode("node1", withInstanceType("m5.large"))
	k8sObj.Spec.ENI.VpcID = "vpc-1"
	k8sObj.Spec.ENI.AvailabilityZone = "eu-west-1a"
	k8sObj.Spec.ENI.NodeSubnetID = nodeSubnetID
	k8sObj.Spec.ENI.SecurityGroups = []string{"sg-1"}

	fake := &fakeOpsNode{mockIPAMNode: mockIPAMNode{instanceID: "i-123", prefixDelegation: true}}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     k8sObj,
		node:       fake,
		enis:       map[string]eniTypes.ENI{},
	}
	n.logger.Store(n.rootLogger)
	fake.ops = n

	// Create an ENI in subnet-x and give it ONE real /28 prefix while the subnet
	// is still healthy (this is the normal partial prefix ENI: a new ENI is born
	// with ceil(toAllocate/16) prefixes, so it has free prefix slots left).
	eniID, _, err := api.CreateNetworkInterface(context.Background(), 0, nodeSubnetID, "desc", []string{"sg-1"}, false, false)
	require.NoError(t, err)
	_, err = api.AttachNetworkInterface(context.Background(), 0, "i-123", eniID)
	require.NoError(t, err)
	require.NoError(t, api.AssignENIPrefixes(context.Background(), eniID, 1), "prefix assignment succeeds while subnet is healthy")

	// Snapshot the ENI state after the prefix is assigned: 1 prefix, plus its 16
	// expanded /28 IPs (and any primary) in Addresses.
	instBefore, err := api.GetInstance(context.Background(), nil, nil, "i-123")
	require.NoError(t, err)
	eniBefore := instBefore.Interfaces[eniID].(*eniTypes.ENI)
	require.Len(t, eniBefore.Prefixes, 1, "ENI starts with exactly one /28 prefix")
	addrsAfterPrefix := len(eniBefore.Addresses)

	// Mirror the prefix ENI into the node view so IsPrefixDelegated stays true
	// (the gate only trips on a zero-prefix ENI). This ENI has a prefix, so the
	// node is still prefix delegated.
	n.enis[eniID] = eniTypes.ENI{
		ID:        eniID,
		IP:        iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
		Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.4"))},
		Prefixes:  eniBefore.Prefixes,
		Subnet:    eniTypes.AwsSubnet{ID: nodeSubnetID},
	}
	require.True(t, n.IsPrefixDelegated(), "node is still prefix delegated (the ENI has a prefix)")

	// Now fragment the subnet: free /32s remain, but no free /28 block.
	api.SetSubnetAtPrefixCapacity(nodeSubnetID, true)

	// Top up the SAME existing prefix ENI. AllocateIPs tries AssignENIPrefixes
	// (fails, subnet at prefix capacity) and falls back to AssignPrivateIpAddresses
	// (/32) on the same ENI.
	a := &nodemanager.AllocationAction{InterfaceID: eniID}
	a.PoolID = ipamTypes.PoolID(nodeSubnetID)
	a.IPv4.AvailableForAllocation = 2
	require.NoError(t, n.AllocateIPs(context.Background(), a), "the /32 fallback succeeds on the existing prefix ENI")

	// Read the ENI back: it now carries BOTH its original /28 prefix AND 2
	// individual /32 secondary IPs. Cilium produced a mixed ENI; there is no guard.
	instAfter, err := api.GetInstance(context.Background(), nil, nil, "i-123")
	require.NoError(t, err)
	eniAfter := instAfter.Interfaces[eniID].(*eniTypes.ENI)
	require.Len(t, eniAfter.Prefixes, 1, "the ENI keeps its /28 prefix")
	require.Len(t, eniAfter.Addresses, addrsAfterPrefix+2,
		"2 individual /32 addresses were added on top of the prefix: this is a MIXED ENI")
	// A mixed ENI has more addresses than its prefixes alone account for.
	require.Greater(t, len(eniAfter.Addresses), 16*len(eniAfter.Prefixes),
		"the ENI carries /32 secondary IPs beyond what its /28 prefix provides (mixed prefix + /32)")
}

// TestFullPrefixDelegatedENIIsNotToppedUpNewENIGetsSlash32 validates the field
// observation that when a node already has a prefix delegated ENI and needs more
// IPs, Cilium adds a NEW ENI (which falls back to /32 in a fragmented subnet)
// rather than adding /32 addresses to the existing /28 ENI.
//
// The reason is structural, not incidental. handleIPAllocation (pkg/ipam/node.go)
// creates a new ENI only when no existing ENI has spare capacity in a subnet that
// still reports free addresses; otherwise it tops up the existing ENI. A prefix
// delegated ENI is "full" once it holds its maximum prefixes: with prefix
// delegation getEffectiveIPLimits returns (limits.IPv4-1)*ENIPDBlockSizeIPv4,
// which for m5.large is (10-1)*16 = 144 addresses = 9 prefixes. At that point
// availableOnENI is 0 and PrepareIPAllocation will not select the ENI for top-up.
// So the existing /28 ENI is left untouched and a new ENI is created for the
// extra demand. In a fragmented subnet that new ENI takes the /32 fallback and
// becomes the zero-prefix ENI that disables prefix delegation node wide.
//
// This is why a mixed ENI is not produced on the steady-state path: by the time a
// second ENI is needed, the first is full, so it is never topped up with /32. A
// mixed ENI only arises if a PARTIAL prefix ENI is topped up while its subnet is
// fragmented, which is the artificial setup in
// TestAllocateIPsProducesMixedPrefixAndSlash32ENI (reachable, but not how the
// allocator behaves once an ENI has been filled).
func TestFullPrefixDelegatedENIIsNotToppedUpNewENIGetsSlash32(t *testing.T) {
	const nodeSubnetID = "subnet-x"
	// Fragmented node subnet: free /32s (100) but no free /28 block.
	x := &ipamTypes.Subnet{ID: nodeSubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 100}
	api := ec2mock.NewAPI(
		[]*ipamTypes.Subnet{x},
		[]*ipamTypes.VirtualNetwork{{ID: "vpc-1"}},
		nil,
		nil,
	)
	api.SetSubnetAtPrefixCapacity(nodeSubnetID, true)
	metaMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(context.Background(), hivetest.Logger(t), api, metaMock)
	require.NoError(t, err)
	instances.subnets = map[string]*ipamTypes.Subnet{nodeSubnetID: x.DeepCopy()}

	k8sObj := newCiliumNode("node1", withInstanceType("m5.large"))
	k8sObj.Spec.ENI.VpcID = "vpc-1"
	k8sObj.Spec.ENI.AvailabilityZone = "eu-west-1a"
	k8sObj.Spec.ENI.NodeSubnetID = nodeSubnetID
	k8sObj.Spec.ENI.SecurityGroups = []string{"sg-1"}

	fake := &fakeOpsNode{mockIPAMNode: mockIPAMNode{instanceID: "i-123", prefixDelegation: true}}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     k8sObj,
		node:       fake,
		enis:       map[string]eniTypes.ENI{},
	}
	n.logger.Store(n.rootLogger)
	fake.ops = n

	// Build a FULL prefix delegated ENI: 9 /28 prefixes and their 144 expanded
	// addresses, the maximum for m5.large. availableOnENI = 144 - 144 = 0.
	var addrs []iputil.Addr
	var prefixes []iputil.Prefix
	for p := range 9 {
		prefixes = append(prefixes, iputil.PrefixFrom(netip.MustParsePrefix(fmt.Sprintf("10.0.%d.0/28", p))))
		for h := range 16 {
			addrs = append(addrs, iputil.AddrFrom(netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", p, h))))
		}
	}
	require.Len(t, addrs, 144)
	n.enis["eni-full-pd"] = eniTypes.ENI{
		ID:        "eni-full-pd",
		IP:        iputil.AddrFrom(netip.MustParseAddr("10.0.255.4")),
		Addresses: addrs,
		Prefixes:  prefixes,
		Subnet:    eniTypes.AwsSubnet{ID: nodeSubnetID},
		Number:    0,
	}
	require.True(t, n.IsPrefixDelegated(), "node is prefix delegated (the existing ENI is all prefixes)")

	// PrepareIPAllocation must NOT select the full prefix ENI for top-up: it has no
	// spare capacity, so there is no interface candidate and no InterfaceID, which
	// means AllocateIPs is never called on it and no /32 is added to the /28 ENI.
	a, err := n.PrepareIPAllocation(hivetest.Logger(t))
	require.NoError(t, err)
	require.Equal(t, 0, a.IPv4.InterfaceCandidates, "the full prefix ENI is not a candidate for top-up")
	require.Empty(t, a.InterfaceID, "no existing ENI is selected, so /32 is never added to the /28 ENI")
	require.Zero(t, a.IPv4.AvailableForAllocation, "nothing can be allocated on the existing ENI")
	require.Positive(t, a.EmptyInterfaceSlots, "a new ENI slot is available, so a new ENI is created instead")

	// Creating the new ENI: in the fragmented subnet it falls back to /32. This is
	// the new /32 ENI the operator observes being added to the node.
	alloc := &nodemanager.AllocationAction{}
	alloc.IPv4.MaxIPsToAllocate = 2
	toAllocate, _, err := n.CreateInterface(context.Background(), alloc, hivetest.Logger(t))
	require.NoError(t, err)
	require.Equal(t, 2, toAllocate)
	require.Equal(t, ipamTypes.PoolID(nodeSubnetID), alloc.PoolID, "the new ENI is created in the node subnet")

	// The original prefix ENI is left exactly as it was: still 9 prefixes and 144
	// addresses, with no individual /32 secondary IPs added to it.
	require.Len(t, n.enis["eni-full-pd"].Prefixes, 9, "the existing /28 ENI keeps all its prefixes")
	require.Len(t, n.enis["eni-full-pd"].Addresses, 144, "no /32 was added to the existing /28 ENI")
}

// TestEndToEndPartiallyUsedPrefixENIIsToppedUpNotNewENI drives the REAL IPAM
// maintenance loop (ipam.NodeManager.MaintainIPPool, which runs PrepareIPAllocation
// then handleIPAllocation then AllocateIPs or CreateInterface) instead of calling
// AllocateIPs directly. It answers the question: when a node already has a prefix
// delegated ENI that is barely used (lots of free prefix capacity) and the subnet
// becomes fragmented (no free /28, but free /32s), does Cilium add /32 to that
// existing ENI, or does it create a NEW ENI?
//
// Verified answer: the existing ENI is topped up with /32 (it becomes a MIXED ENI
// with both a /28 prefix and individual /32 addresses), and NO new ENI is created.
// This is the authoritative behavior of the real allocation loop, and it matches
// Cilium's own TestNodeManagerPrefixDelegation (which adds a single /32 on the
// fallback, not a new ENI). A new ENI is created only once the existing ENI is
// full (see TestFullPrefixDelegatedENIIsNotToppedUpNewENIGetsSlash32).
func TestEndToEndPartiallyUsedPrefixENIIsToppedUpNotNewENI(t *testing.T) {
	setup(t)
	const instanceID = "i-e2e-partial-pd-0"

	pdTestSubnet := *testSubnet
	pdTestSubnet.AvailableAddresses = 1000
	ec2api := ec2mock.NewAPI([]*ipamTypes.Subnet{&pdTestSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), ec2api, metadataMockapi)
	require.NoError(t, err)

	// One prefix delegated ENI on the node (index 0), created while the subnet is
	// healthy so it gets a real /28 prefix.
	eniID1, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, pdTestSubnet.ID, "desc", []string{"sg1", "sg2"}, true, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID1)
	require.NoError(t, err)
	instances.Resync(t.Context())

	mngr, err := nodemanager.NewNodeManager(hivetest.Logger(t), instances, k8sapi, metricsapi, 10, false, 0, true)
	require.NoError(t, err)

	cn := newCiliumNode("node1", withInstanceID(instanceID), withInstanceType("m5.large"), withIPAMPreAllocate(8))
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))
	node := mngr.Get("node1")
	require.NotNil(t, node)
	// The node has a single prefix delegated ENI with 16 IPs (one /28) and 0 used:
	// barely used, with room for 8 more prefixes.
	require.Equal(t, 16, node.Stats().IPv4.AvailableIPs, "node starts with one /28 prefix")
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Fragment the subnet: free /32s remain (1000) but no free /28 block.
	ec2api.SetSubnetAtPrefixCapacity(pdTestSubnet.ID, true)

	// Create a deficit on the barely-used ENI (use 12 of 16, so the node needs
	// 12 + PreAllocate(8) = 20 available).
	mngr.Upsert(updateCiliumNode(cn, 16, 12))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 10*time.Second))
	node = mngr.Get("node1")
	require.NotNil(t, node)

	node.Ops().PopulateStatusFields(cn)

	// The real loop topped up the EXISTING ENI with /32, it did NOT create a new ENI.
	require.Len(t, cn.Status.ENI.ENIs, 1, "no new ENI was created; the existing ENI was topped up")
	existing := cn.Status.ENI.ENIs[eniID1]
	require.Len(t, existing.Prefixes, 1, "the existing ENI keeps its single /28 prefix")
	// 16 IPs from the /28 prefix plus 4 individual /32 addresses = 20: a MIXED ENI.
	require.Greater(t, len(existing.Addresses), 16*len(existing.Prefixes),
		"the existing ENI now carries individual /32 addresses on top of its /28 prefix (mixed)")
	require.Equal(t, 20, node.Stats().IPv4.AvailableIPs, "deficit resolved by adding /32 to the existing ENI (16 -> 20)")
	require.Equal(t, 12, node.Stats().IPv4.UsedIPs)
}

// TestPrepareIPAllocationSkipsExistingENIWhenSubnetReportsNoFreeAddresses pins the
// one condition under which a barely-used existing prefix ENI is NOT topped up and
// Cilium creates a new ENI instead. The default behavior (verified by
// TestEndToEndPartiallyUsedPrefixENIIsToppedUpNotNewENI) is to top up the existing
// ENI, but PrepareIPAllocation only selects an existing ENI for top-up when its
// subnet's cached AvailableAddresses is greater than 0:
//
//	if subnet := n.manager.GetSubnet(e.Subnet.ID); subnet != nil {
//	    if subnet.AvailableAddresses > 0 && a.InterfaceID == "" { ... select it ... }
//	}
//
// If the subnet reports zero free addresses, the existing ENI is skipped even
// though it still has spare prefix capacity, so AllocateIPs is never called on it
// (no /32 is added to the /28 ENI) and handleIPAllocation creates a new ENI
// instead. The reporter described exactly this input: the fragmented subnet
// "reported fewer available IPs due to AWS address reservations". When those
// reservations drive the reported AvailableIpAddressCount to zero, this is the
// code path that produces "a new ENI is added, the existing /28 ENI is untouched"
// even when that ENI is barely used.
func TestPrepareIPAllocationSkipsExistingENIWhenSubnetReportsNoFreeAddresses(t *testing.T) {
	const nodeSubnetID = "subnet-x"
	// Subnet reports ZERO free addresses (AWS reservations counted as used), even
	// though in reality it is only /28-fragmented and still has assignable /32s.
	x := &ipamTypes.Subnet{ID: nodeSubnetID, VirtualNetworkID: "vpc-1", AvailabilityZone: "eu-west-1a", AvailableAddresses: 0}
	api := ec2mock.NewAPI(
		[]*ipamTypes.Subnet{x},
		[]*ipamTypes.VirtualNetwork{{ID: "vpc-1"}},
		nil,
		nil,
	)
	metaMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(context.Background(), hivetest.Logger(t), api, metaMock)
	require.NoError(t, err)
	instances.subnets = map[string]*ipamTypes.Subnet{nodeSubnetID: x.DeepCopy()}

	k8sObj := newCiliumNode("node1", withInstanceType("m5.large"))
	k8sObj.Spec.ENI.VpcID = "vpc-1"
	k8sObj.Spec.ENI.AvailabilityZone = "eu-west-1a"
	k8sObj.Spec.ENI.NodeSubnetID = nodeSubnetID

	fake := &fakeOpsNode{mockIPAMNode: mockIPAMNode{instanceID: "i-123", prefixDelegation: true}}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     k8sObj,
		node:       fake,
		enis:       map[string]eniTypes.ENI{},
	}
	n.logger.Store(n.rootLogger)
	fake.ops = n

	// A barely-used prefix ENI: one /28 (16 addresses), lots of free prefix room.
	var addrs []iputil.Addr
	for i := range 16 {
		addrs = append(addrs, iputil.AddrFrom(netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i+16))))
	}
	n.enis["eni-pd"] = eniTypes.ENI{
		ID:        "eni-pd",
		IP:        iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
		Addresses: addrs,
		Prefixes:  []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28"))},
		Subnet:    eniTypes.AwsSubnet{ID: nodeSubnetID},
		Number:    0,
	}
	require.True(t, n.IsPrefixDelegated(), "node is prefix delegated")

	a, err := n.PrepareIPAllocation(hivetest.Logger(t))
	require.NoError(t, err)
	// The ENI has spare prefix capacity, so it is counted as a candidate ...
	require.Equal(t, 1, a.IPv4.InterfaceCandidates, "the barely-used ENI has spare prefix capacity")
	// ... but it is NOT selected for top-up because its subnet reports no free
	// addresses, so AllocateIPs is never called on it and no /32 is added to it.
	require.Empty(t, a.InterfaceID, "existing ENI is skipped when its subnet reports zero free addresses")
	require.Zero(t, a.IPv4.AvailableForAllocation, "nothing is allocated on the existing ENI")
	// A free interface slot remains, so handleIPAllocation creates a NEW ENI.
	require.Positive(t, a.EmptyInterfaceSlots, "a new ENI is created instead of topping up the existing one")
}
