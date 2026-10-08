// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/aws/api/mock"
	"github.com/cilium/cilium/pkg/aws/ipam/limits"
	"github.com/cilium/cilium/pkg/aws/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// TestResyncInterfacesAndIPsLockOrder verifies that this Node never calls into
// the operator's nodemanager.Node while holding its own lock. The operator side
// holds nodemanager.Node.mutex across downcalls into ops (GetAttachedCIDRs,
// GetMaximumAllocatableIPv4), both of which take our lock, so an upcall from
// under our lock closes an AB-BA cycle that wedges the whole ENI allocator.
//
// The onInstanceID hook stands in for the operator: it tries to take our lock
// from another goroutine while the upcall is in flight, which is exactly what
// the nodemanager does, and fails the test if it cannot.
func TestResyncInterfacesAndIPsLockOrder(t *testing.T) {
	const instanceID = "i-testLockOrder-0"

	mockEC2API := mock.NewAPI(nil, nil, nil, nil)
	limitsGetter, err := limits.NewLimitsGetter(hivetest.Logger(t), mockEC2API, limits.TriggerMinInterval, limits.EC2apiTimeout, limits.EC2apiRetryCount)
	require.NoError(t, err)

	cn := newCiliumNode("node1", withInstanceType("m5.large"),
		func(cn *v2.CiliumNode) {
			cn.Spec.InstanceID = instanceID
		},
	)
	im := ipamTypes.NewInstanceMap()
	im.Update(instanceID, &types.ENI{ID: "eni-a"})

	ipamNode := &mockIPAMNode{instanceID: instanceID}
	n := &Node{
		rootLogger: hivetest.Logger(t),
		node:       ipamNode,
		k8sObj:     cn,
		manager: &InstancesManager{
			logger:       hivetest.Logger(t),
			instances:    im,
			ec2api:       mockEC2API,
			limitsGetter: limitsGetter,
		},
		enis: map[string]types.ENI{},
	}
	n.logger.Store(hivetest.Logger(t))
	ipamNode.ops = n

	var upcalls int
	ipamNode.onInstanceID = func() {
		upcalls++
		acquired := make(chan struct{})
		go func() {
			n.mutex.Lock()
			n.mutex.Unlock()
			close(acquired)
		}()
		select {
		case <-acquired:
		case <-time.After(5 * time.Second):
			t.Error("Node.mutex is held across the upcall into n.node, inverting the lock order with nodemanager.Node")
		}
	}

	_, _, err = n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	require.NoError(t, err)

	n.PopulateStatusFields(cn.DeepCopy())

	// Guard against the hook silently never running.
	require.Equal(t, 2, upcalls)
}
