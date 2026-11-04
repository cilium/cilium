// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apiMock "github.com/cilium/cilium/pkg/aws/api/mock"
	"github.com/cilium/cilium/pkg/aws/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/resynctest"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/time"
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

func (h *hookedEC2API) setHook(hook func()) {
	h.afterGetInstances = hook
}

// newHookedInstancesManager also returns the ID of the ENI it attaches to instanceID.
func newHookedInstancesManager(t *testing.T, instanceID string) (*apiMock.API, *hookedEC2API, *InstancesManager, string) {
	ec2api := apiMock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	hooked := &hookedEC2API{EC2API: ec2api}
	mngr, err := NewInstancesManager(t.Context(), hivetest.Logger(t), hooked, metadataMockapi)
	require.NoError(t, err)

	eniID, _, err := ec2api.CreateNetworkInterface(t.Context(), 4, testSubnet.ID, "desc", []string{"sg-1"}, false, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID)
	require.NoError(t, err)
	_, err = mngr.Resync(t.Context())
	require.NoError(t, err)
	return ec2api, hooked, mngr, eniID
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

func TestFullResync(t *testing.T) {
	const instanceID = "i-1"

	t.Run("IPRelease", func(t *testing.T) {
		t.Parallel()
		ec2api, hooked, mngr, eniID := newHookedInstancesManager(t, instanceID)
		addrs := cachedENIAddresses(mngr, instanceID)
		require.NotEmpty(t, addrs)
		released := addrs[0]

		resynctest.RunDuringResync(t, mngr, hooked.setHook,
			func() error {
				return ec2api.UnassignPrivateIpAddresses(context.Background(), eniID, []string{released})
			},
			func() {
				mngr.RemoveIPsFromENI(instanceID, eniID, []string{released})
			})

		require.NotContains(t, cachedENIAddresses(mngr, instanceID), released)
		require.Len(t, cachedENIAddresses(mngr, instanceID), len(addrs)-1)
	})

	t.Run("ENIUpdate", func(t *testing.T) {
		t.Parallel()
		ec2api, hooked, mngr, _ := newHookedInstancesManager(t, instanceID)
		resynctest.ENIUpdate(t, mngr, hooked.setHook, instanceID, func() (string, *types.ENI, error) {
			eniID, eni, err := ec2api.CreateNetworkInterface(context.Background(), 4, testSubnet.ID, "desc", []string{"sg-1"}, false, false)
			if err != nil {
				return "", nil, err
			}
			if _, err := ec2api.AttachNetworkInterface(context.Background(), 1, instanceID, eniID); err != nil {
				return "", nil, err
			}
			eni.Number = 1
			return eniID, eni, nil
		})
	})

	t.Run("InstanceDelete", func(t *testing.T) {
		t.Parallel()
		_, hooked, mngr, _ := newHookedInstancesManager(t, instanceID)
		resynctest.InstanceDelete(t, mngr, hooked.setHook, instanceID)
	})
}

// instanceSyncResyncer runs the shared fetch-window helper against a partial sync.
type instanceSyncResyncer struct {
	manager    *InstancesManager
	instanceID string
}

func (r instanceSyncResyncer) Resync(ctx context.Context) (time.Time, error) {
	return r.manager.InstanceSync(ctx, r.instanceID)
}

type hookedInstanceEC2API struct {
	EC2API
	afterGetInstance func()
	hookCalled       atomic.Bool
}

func (h *hookedInstanceEC2API) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	instance, err := h.EC2API.GetInstance(ctx, vpcs, subnets, instanceID)
	// Only delay the first snapshot; a concurrent InstanceSync must be able to
	// fetch the newer cloud state without entering the same hook again.
	if h.afterGetInstance != nil && h.hookCalled.CompareAndSwap(false, true) {
		h.afterGetInstance()
	}
	return instance, err
}

func TestInstanceSyncPreservesConcurrentCacheChanges(t *testing.T) {
	const (
		instanceID = "i-partial-sync"
		eniID      = "eni-1"
		retainedIP = "10.0.0.1"
		releasedIP = "10.0.0.2"
		addedIP    = "10.0.0.3"
	)
	initialENI := &types.ENI{
		ID: eniID,
		Addresses: []iputil.Addr{
			iputil.AddrFrom(netip.MustParseAddr(retainedIP)),
			iputil.AddrFrom(netip.MustParseAddr(releasedIP)),
		},
	}
	newENI := &types.ENI{ID: "eni-2", Description: "new ENI"}
	addedENI := initialENI.DeepCopy()
	addedENI.Addresses = append(addedENI.Addresses, iputil.AddrFrom(netip.MustParseAddr(addedIP)))
	releasedENI := initialENI.DeepCopy()
	releasedENI.Addresses = releasedENI.Addresses[:1]

	tests := []struct {
		name   string
		want   apiMock.ENIMap
		update func(context.Context, *InstancesManager) error
	}{
		{
			name: "UpdateENI",
			want: apiMock.ENIMap{eniID: initialENI, newENI.ID: newENI},
			update: func(_ context.Context, m *InstancesManager) error {
				m.UpdateENI(instanceID, newENI)
				return nil
			},
		},
		{
			name: "InstanceSync",
			want: apiMock.ENIMap{eniID: initialENI, newENI.ID: newENI},
			update: func(ctx context.Context, m *InstancesManager) error {
				_, err := m.InstanceSync(ctx, instanceID)
				return err
			},
		},
		{
			name: "AddIPsToENI",
			want: apiMock.ENIMap{eniID: addedENI},
			update: func(_ context.Context, m *InstancesManager) error {
				m.AddIPsToENI(instanceID, eniID, []string{addedIP})
				return nil
			},
		},
		{
			name: "RemoveIPsFromENI",
			want: apiMock.ENIMap{eniID: releasedENI},
			update: func(_ context.Context, m *InstancesManager) error {
				m.RemoveIPsFromENI(instanceID, eniID, []string{releasedIP})
				return nil
			},
		},
		{
			name: "DeleteInstance",
			want: apiMock.ENIMap{},
			update: func(_ context.Context, m *InstancesManager) error {
				m.DeleteInstance(instanceID)
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cloud := apiMock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
			cloud.UpdateENIs(map[string]apiMock.ENIMap{instanceID: {eniID: initialENI}})
			hooked := &hookedInstanceEC2API{EC2API: cloud}
			manager, err := NewInstancesManager(t.Context(), hivetest.Logger(t), hooked, metadataMockapi)
			require.NoError(t, err)
			_, err = manager.Resync(t.Context())
			require.NoError(t, err)
			require.True(t, manager.HasInstance(instanceID))

			var updateErr error
			resynctest.RunDuringResync(t,
				instanceSyncResyncer{manager: manager, instanceID: instanceID},
				func(hook func()) { hooked.afterGetInstance = hook },
				func() error {
					// The partial sync has already captured initialENI. Change
					// AWS now so its delayed response contains the older state.
					cloud.UpdateENIs(map[string]apiMock.ENIMap{instanceID: test.want})
					return nil
				},
				func() { updateErr = test.update(t.Context(), manager) },
			)
			require.NoError(t, updateErr)

			// After both operations finish, the old snapshot must not undo
			// the ENI/IP change or resurrect a deleted instance.
			cached := apiMock.ENIMap{}
			manager.ForeachInstance(instanceID, func(_, eniID string, iface ipamTypes.Interface) error {
				cached[eniID] = iface.(*types.ENI)
				return nil
			})
			require.Equal(t, test.want, cached)
			require.Equal(t, len(test.want) > 0, manager.HasInstance(instanceID))
		})
	}
}
