// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cilium/ipam/cidrset"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8s_testing "k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/ipam/allocator/podcidr"
	"github.com/cilium/cilium/pkg/ipam/types"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
)

// TestPodCIDRAllocatorOverlap tests that, on startup all nodes with assigned podCIDRs are processed so that nodes
// without pod CIDRs will not get the same CIDR ranges assigned as existing nodes.
func TestPodCIDRAllocatorOverlap(t *testing.T) {
	// We need to run the test multiple times since we are testing a race condition which is dependant on the order
	// of a hash map.
	for i := 0; i < 5; i++ {
		fmt.Printf("Run %d/5\n", i+1)

		podCIDRAllocatorOverlapTestRun(t)

		// Reset synced chanel after test run
		k8sCiliumNodesCacheSynced = make(chan struct{})
	}
}

func podCIDRAllocatorOverlapTestRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a new CIDR allocator

	_, cidr, err := net.ParseCIDR("10.129.0.0/16")
	if err != nil {
		panic(err)
	}

	set, err := cidrset.NewCIDRSet(cidr, 24)
	if err != nil {
		panic(err)
	}

	// Create a mock APIServer client where we have 2 existing nodes, one with a PodCIDR and one without.
	// When List'ed from the client, first node-a is returned then node-b

	fakeClient := cilium_fake.NewSimpleClientset(&cilium_api_v2.CiliumNode{
		ObjectMeta: v1.ObjectMeta{
			Name: "node-a",
		},
		Spec: cilium_api_v2.NodeSpec{
			IPAM: types.IPAMSpec{
				PodCIDRs: []string{},
			},
		},
	}, &cilium_api_v2.CiliumNode{
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
	})

	// Sync channel to know when the APIServer state is stable.
	updated := make(chan struct{})
	var timer *time.Timer

	// Add a reactor to the fake client, the callback is triggered for each Update to the APIServer.
	poolReactor := &k8s_testing.SimpleReactor{
		Verb:     "update",
		Resource: "ciliumnodes",
		Reaction: func(action k8s_testing.Action) (handled bool, ret runtime.Object, err error) {
			// This closure is called for every API calls made to the mocked client.
			// We expect, upon starting the node manager to get a burst of update events. We want to conclude the test
			// as soon as the last update of this burst has occurred. We do this by starting a timer on the first ever
			// call and resetting it for every subsequent call. Assuming the interval between calls in the bursts are
			// less than 1 second, the timer should elapse 1 second after the last event and close the `updated` channel
			// which will signal the main test thread to perform the check.
			if timer == nil {
				timer = time.NewTimer(time.Second)
				go func() {
					<-timer.C
					close(updated)
				}()
			} else {
				timer.Reset(time.Second)
			}

			return false, nil, nil
		},
	}
	fakeClient.ReactionChain = append([]k8s_testing.Reactor{poolReactor}, fakeClient.ReactionChain...)

	// Make a set out of the fake cilium client.
	fakeSet := &k8sClient.FakeClientset{
		CiliumFakeClientset: fakeClient,
	}

	// Create a new pod manager with only our IPv4 allocator and fake client set.
	podCidrManager := podcidr.NewNodesPodCIDRManager([]podcidr.CIDRAllocator{
		set,
	}, nil, &ciliumNodeUpdateImplementation{clientset: fakeSet}, nil)

	// start synchronization.
	if err := startSynchronizingCiliumNodes(ctx, fakeSet, podCidrManager, false); err != nil {
		t.Fatal(err)
	}

	// Wait for the "cache synced" signal, just like we would normally.
	<-k8sCiliumNodesCacheSynced

	// Trigger the Resync after the cache sync signal
	podCidrManager.Resync(ctx, time.Time{})

	// Now wait until the APIServer state is stable
	<-updated

	// Get node A from the mock APIServer
	nodeAInt, err := fakeClient.Tracker().Get(ciliumnodesResource, "", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	nodeA := nodeAInt.(*cilium_api_v2.CiliumNode)

	// Get node B from the mock APIServer
	nodeBInt, err := fakeClient.Tracker().Get(ciliumnodesResource, "", "node-b")
	if err != nil {
		t.Fatal(err)
	}
	nodeB := nodeBInt.(*cilium_api_v2.CiliumNode)

	if len(nodeA.Spec.IPAM.PodCIDRs) != 1 {
		t.Fatal("Node A has no PodCIDRs")
	}

	if len(nodeB.Spec.IPAM.PodCIDRs) != 1 {
		t.Fatal("Node B has no PodCIDRs")
	}

	// The PodCIDRs should be distinct.
	if nodeA.Spec.IPAM.PodCIDRs[0] == nodeB.Spec.IPAM.PodCIDRs[0] {
		t.Fatal("Node A and Node B are assigned overlapping PodCIDRs")
	}
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
