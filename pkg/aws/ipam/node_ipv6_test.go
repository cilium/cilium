// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	apiMock "github.com/cilium/cilium/pkg/aws/api/mock"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// newWiredNode builds a *Node backed by the EC2 mock API with a single primary
// ENI attached to instanceID and the manager resynced. The returned node is
// wired exactly like production: n.node.Ops() returns the AWS *Node itself, so
// methods that call n.node.Ops() (AllocateIPs, CreateInterface) work.
func newWiredNode(t *testing.T, instanceID, instanceType string) (*Node, *apiMock.API, *InstancesManager) {
	t.Helper()

	ec2api := apiMock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), ec2api, metadataMockapi)
	require.NoError(t, err)

	eniID, _, err := ec2api.CreateNetworkInterface(t.Context(), 0, testSubnet.ID, "primary", []string{"sg-1"}, false, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID)
	require.NoError(t, err)
	_, err = instances.Resync(t.Context())
	require.NoError(t, err)

	defOpts := []func(*v2.CiliumNode){
		withTestDefaults(),
		withInstanceID(instanceID),
		withInstanceType(instanceType),
		withNodeSubnetID(testSubnet.ID),
	}
	cn := newCiliumNode("node1", defOpts...)

	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		k8sObj:     cn,
		instanceID: instanceID,
	}
	n.node = &mockIPAMNode{instanceID: instanceID, ops: n}
	n.logger.Store(n.rootLogger)

	// Populate n.enis from the manager's view.
	_, _, err = n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	require.NoError(t, err)

	return n, ec2api, instances
}

// primaryENIID returns the ID of the node's primary (index 0) ENI.
func primaryENIID(t *testing.T, n *Node) string {
	t.Helper()
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	for id, eni := range n.enis {
		if eni.Number == 0 {
			return id
		}
	}
	t.Fatal("no primary ENI found")
	return ""
}

// attachedIPv6Prefixes resyncs from the EC2 mock and returns the IPv6 prefixes
// currently attached across all of the node's ENIs.
func attachedIPv6Prefixes(t *testing.T, n *Node, instances *InstancesManager) []netip.Prefix {
	t.Helper()
	_, err := instances.Resync(t.Context())
	require.NoError(t, err)
	_, _, err = n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	require.NoError(t, err)

	var v6 []netip.Prefix
	for _, p := range n.GetAttachedCIDRs() {
		if p.Addr().Is6() {
			v6 = append(v6, p)
		}
	}
	return v6
}

func TestAllocateIPs_IPv6Prefix(t *testing.T) {
	n, _, instances := newWiredNode(t, "i-allocate-ipv6", "m5.large")
	eniID := primaryENIID(t, n)

	// Sanity: no IPv6 prefixes attached yet.
	require.Empty(t, attachedIPv6Prefixes(t, n, instances))

	a := &nodemanager.AllocationAction{InterfaceID: eniID}
	a.IPv6.MaxPrefixesToAllocate = 1

	require.NoError(t, n.AllocateIPs(t.Context(), a))

	require.Len(t, attachedIPv6Prefixes(t, n, instances), 1)
}

func TestAllocateIPs_NoIPv6WhenNotRequested(t *testing.T) {
	n, _, instances := newWiredNode(t, "i-allocate-no-ipv6", "m5.large")
	eniID := primaryENIID(t, n)

	a := &nodemanager.AllocationAction{InterfaceID: eniID}
	a.IPv4.AvailableForAllocation = 2
	// IPv6.MaxPrefixesToAllocate left at 0.

	require.NoError(t, n.AllocateIPs(t.Context(), a))

	require.Empty(t, attachedIPv6Prefixes(t, n, instances))
}

func TestCreateInterface_IPv6Only(t *testing.T) {
	// Request a new ENI for IPv6 only (no IPv4 addresses).
	n, _, instances := newWiredNode(t, "i-create-ipv6", "m5.large")

	a := &nodemanager.AllocationAction{}
	a.IPv6.MaxPrefixesToAllocate = 1
	// IPv4.MaxIPsToAllocate left at 0.

	toAllocate, errStr, err := n.CreateInterface(t.Context(), a, hivetest.Logger(t))
	require.NoError(t, err)
	require.Empty(t, errStr)
	require.Equal(t, 0, toAllocate)

	// The node should now have a primary ENI plus the freshly created one,
	// and exactly one IPv6 prefix attached.
	require.Len(t, attachedIPv6Prefixes(t, n, instances), 1)

	n.mutex.RLock()
	require.Len(t, n.enis, 2)
	n.mutex.RUnlock()
}
