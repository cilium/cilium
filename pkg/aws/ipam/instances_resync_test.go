// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apiMock "github.com/cilium/cilium/pkg/aws/api/mock"
	"github.com/cilium/cilium/pkg/aws/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

// hookedEC2API calls afterGetInstances while a full resync holds its EC2 snapshot.
type hookedEC2API struct {
	EC2API
	afterGetInstances func()
}

func (h *hookedEC2API) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances, err := h.EC2API.GetInstances(ctx, vpcs, subnets)
	if h.afterGetInstances != nil {
		h.afterGetInstances()
	}
	return instances, err
}

func cachedENIAddresses(m *InstancesManager, instanceID string) (addrs []string) {
	m.ForeachInstance(instanceID, func(_, _ string, iface ipamTypes.Interface) error {
		eni, ok := iface.(*types.ENI)
		if !ok {
			return nil
		}
		for _, addr := range eni.Addresses {
			addrs = append(addrs, addr.String())
		}
		return nil
	})
	return addrs
}

func cachedENIIDs(m *InstancesManager, instanceID string) (ids []string) {
	m.ForeachInstance(instanceID, func(_, ifaceID string, _ ipamTypes.Interface) error {
		ids = append(ids, ifaceID)
		return nil
	})
	return ids
}

// runDuringFullResync runs ec2Setup and then cacheUpdate inside the EC2 fetch window of a full resync.
func runDuringFullResync(t *testing.T, hooked *hookedEC2API, instances *InstancesManager, ec2Setup func() error, cacheUpdate func()) {
	t.Helper()

	// An unguarded cacheUpdate must land within this much of the fetch window for the resync to drop it.
	const detectionBudget = 2 * time.Second
	// Only a locking regression keeps ec2Setup or cacheUpdate waiting this long.
	const progressTimeout = 10 * time.Second

	var setupErr error
	var windows int
	var setupStalled bool
	atCacheUpdate := make(chan struct{})
	done := make(chan struct{})
	hookReturned := make(chan struct{})

	// The resync goroutine runs this hook, so it records what it saw and never calls t itself.
	hooked.afterGetInstances = func() {
		defer close(hookReturned)
		windows++
		go func() {
			defer close(done)
			if setupErr = ec2Setup(); setupErr != nil {
				return
			}
			close(atCacheUpdate)
			cacheUpdate()
		}()

		// Keep the EC2 calls out of the budget below, and never wait on a setup that gave up.
		select {
		case <-atCacheUpdate:
		case <-done:
			return
		case <-time.After(progressTimeout):
			setupStalled = true
			return
		}

		// A guarded cacheUpdate waits for resyncLock, so this select always spends the whole budget.
		select {
		case <-done:
		case <-time.After(detectionBudget):
		}
	}

	resynced := make(chan error, 1)
	go func() {
		_, err := instances.Resync(t.Context())
		resynced <- err
	}()

	// The hook owns progressTimeout plus the budget, so wait that out before blaming the resync.
	select {
	case <-hookReturned:
	case <-time.After(progressTimeout + detectionBudget + time.Second):
		t.Fatalf("the full resync did not reach its EC2 fetch hook within %v", progressTimeout)
	}
	require.False(t, setupStalled, "EC2 setup neither reached the cache update nor failed within %v", progressTimeout)

	// A cacheUpdate that takes the locks in the wrong order deadlocks the publish after the hook.
	select {
	case err := <-resynced:
		require.NoError(t, err)
	case <-time.After(progressTimeout):
		t.Fatalf("the full resync did not publish within %v of its fetch window; cacheUpdate holds a lock it needs", progressTimeout)
	}

	select {
	case <-done:
	case <-time.After(progressTimeout):
		t.Fatalf("cache update still blocked %v after the full resync released resyncLock", progressTimeout)
	}

	hooked.afterGetInstances = nil
	require.NoError(t, setupErr)
	// Guard against the hook silently never running.
	require.Equal(t, 1, windows)
}

// TestFullResyncKeepsConcurrentIPRelease releases an IP inside a full resync's fetch window.
func TestFullResyncKeepsConcurrentIPRelease(t *testing.T) {
	const instanceID = "i-testFullResyncKeepsConcurrentIPRelease"

	ec2api := apiMock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	hooked := &hookedEC2API{EC2API: ec2api}
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), hooked, metadataMockapi)
	require.NoError(t, err)

	eniID, _, err := ec2api.CreateNetworkInterface(t.Context(), 4, testSubnet.ID, "desc", []string{"sg-1"}, false, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID)
	require.NoError(t, err)
	_, err = instances.Resync(t.Context())
	require.NoError(t, err)

	addrs := cachedENIAddresses(instances, instanceID)
	require.NotEmpty(t, addrs)
	released := addrs[0]

	runDuringFullResync(t, hooked, instances,
		func() error {
			return ec2api.UnassignPrivateIpAddresses(context.Background(), eniID, []string{released})
		},
		func() {
			instances.RemoveIPsFromENI(instanceID, eniID, []string{released})
		})

	require.NotContains(t, cachedENIAddresses(instances, instanceID), released)
	require.Len(t, cachedENIAddresses(instances, instanceID), len(addrs)-1)
}

// TestFullResyncKeepsConcurrentENIUpdate attaches an ENI inside a full resync's fetch window.
func TestFullResyncKeepsConcurrentENIUpdate(t *testing.T) {
	const instanceID = "i-testFullResyncKeepsConcurrentENIUpdate"

	ec2api := apiMock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	hooked := &hookedEC2API{EC2API: ec2api}
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), hooked, metadataMockapi)
	require.NoError(t, err)

	attachedENI, _, err := ec2api.CreateNetworkInterface(t.Context(), 4, testSubnet.ID, "desc", []string{"sg-1"}, false, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, attachedENI)
	require.NoError(t, err)
	_, err = instances.Resync(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{attachedENI}, cachedENIIDs(instances, instanceID))

	var createdENI string
	var createdIface *types.ENI
	runDuringFullResync(t, hooked, instances,
		func() (err error) {
			createdENI, createdIface, err = ec2api.CreateNetworkInterface(context.Background(), 4, testSubnet.ID, "desc", []string{"sg-1"}, false, false)
			if err != nil {
				return err
			}
			if _, err = ec2api.AttachNetworkInterface(context.Background(), 1, instanceID, createdENI); err != nil {
				return err
			}
			createdIface.Number = 1
			return nil
		},
		func() {
			instances.UpdateENI(instanceID, createdIface)
		})

	require.ElementsMatch(t, []string{attachedENI, createdENI}, cachedENIIDs(instances, instanceID))
}
