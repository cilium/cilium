// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool/cidralloc"
	"github.com/cilium/cilium/pkg/ipam/allocator/podcidr"
	"github.com/cilium/cilium/pkg/ipam/cidrset"
	"github.com/cilium/cilium/pkg/ipam/types"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
)

// TestPodCIDRAllocatorOverlap tests that, on startup all nodes with assigned podCIDRs are processed so that nodes
// without pod CIDRs will not get the same CIDR ranges assigned as existing nodes.
func TestPodCIDRAllocatorOverlap(t *testing.T) {
	// We need to run the test multiple times since we are testing a race condition which is dependant on the order
	// of a hash map.
	for i := range 5 {
		fmt.Printf("Run %d/5\n", i+1)

		podCIDRAllocatorOverlapTestRun(t)
	}
}

func podCIDRAllocatorOverlapTestRun(t *testing.T) {
	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Create a new CIDR allocator

	_, cidr, err := net.ParseCIDR("10.129.0.0/16")
	require.NoError(t, err)

	set, err := cidrset.NewCIDRSet(cidr, 24)
	require.NoError(t, err)

	// Create a mock APIServer client where we have 2 existing nodes, one with a PodCIDR and one without.
	// When List'ed from the client, first node-a is returned then node-b

	// Use NewFakeClientset to get proper WatchList semantics support
	fakeSet, _ := k8sClient.NewFakeClientset(hivetest.Logger(t))

	// Add the initial nodes to the tracker
	nodeA := &cilium_api_v2.CiliumNode{
		ObjectMeta: v1.ObjectMeta{
			Name: "node-a",
		},
		Spec: cilium_api_v2.NodeSpec{
			IPAM: types.IPAMSpec{
				PodCIDRs: []string{},
			},
		},
	}
	nodeB := &cilium_api_v2.CiliumNode{
		ObjectMeta: v1.ObjectMeta{
			Name: "node-b",
		},
		Spec: cilium_api_v2.NodeSpec{
			IPAM: types.IPAMSpec{
				PodCIDRs: []string{
					"10.129.0.0/24",
				},
			},
		},
	}
	require.NoError(t, fakeSet.CiliumFakeClientset.Tracker().Add(nodeA))
	require.NoError(t, fakeSet.CiliumFakeClientset.Tracker().Add(nodeB))

	ciliumNodes, err := operatorK8s.CiliumNodeResource(hivetest.Lifecycle(t), fakeSet, nil)
	require.NoError(t, err)

	// Create a new pod manager with only our IPv4 allocator and fake client set.
	podCidrManager := podcidr.NewNodesPodCIDRManager(hivetest.Logger(t), []cidralloc.CIDRAllocator{
		set,
	}, nil, &ciliumNodeUpdateImplementation{clientset: fakeSet}, nil)

	// start synchronization.
	wg.Go(func() {
		watchCiliumNodes(ctx, ciliumNodes, podCidrManager, true)
	})

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		// Get node A from the mock APIServer
		nodeAInt, err := fakeSet.CiliumFakeClientset.Tracker().Get(ciliumnodesResource, "", "node-a")
		if !assert.NoError(c, err) {
			return
		}
		nodeA := nodeAInt.(*cilium_api_v2.CiliumNode)

		// Get node B from the mock APIServer
		nodeBInt, err := fakeSet.CiliumFakeClientset.Tracker().Get(ciliumnodesResource, "", "node-b")
		if !assert.NoError(c, err) {
			return
		}
		nodeB := nodeBInt.(*cilium_api_v2.CiliumNode)

		if !assert.Len(c, nodeA.Spec.IPAM.PodCIDRs, 1) {
			return
		}

		if !assert.Len(c, nodeB.Spec.IPAM.PodCIDRs, 1) {
			return
		}

		assert.NotEqual(c, nodeA.Spec.IPAM.PodCIDRs, nodeB.Spec.IPAM.PodCIDRs,
			"Node A and Node B should not be assigned overlapping PodCIDRs")
	}, 2*time.Minute, 10*time.Millisecond)
}

var ciliumnodesResource = schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnodes"}

type MockObserver struct{}

// PostRun is called after a trigger run with the call duration, the
// latency between 1st queue request and the call run and the number of
// queued events folded into the last run
func (o *MockObserver) PostRun(callDuration, latency time.Duration, folds int) {}

// QueueEvent is called when Trigger() is called to schedule a trigger
// run
func (o *MockObserver) QueueEvent(reason string) {}
