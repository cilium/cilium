// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apimock "github.com/cilium/cilium/pkg/alibabacloud/api/mock"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/ipam/resynctest"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/time"
)

// hookedAPI calls afterGetInstances while a full resync holds its ECS snapshot.
type hookedAPI struct {
	AlibabaCloudAPI
	afterGetInstances func()
}

func (h *hookedAPI) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances, err := h.AlibabaCloudAPI.GetInstances(ctx, vpcs, subnets)
	if h.afterGetInstances != nil {
		h.afterGetInstances()
	}
	return instances, err
}

func (h *hookedAPI) setHook(hook func()) {
	h.afterGetInstances = hook
}

func newHookedInstancesManager(t *testing.T) (*apimock.API, *hookedAPI, *InstancesManager) {
	api := apimock.NewAPI(subnets, vpcs, securityGroups)
	api.UpdateENIs(primaryENIs)
	hooked := &hookedAPI{AlibabaCloudAPI: api}
	mngr := NewInstancesManager(hivetest.Logger(t), hooked)
	_, err := mngr.Resync(t.Context())
	require.NoError(t, err)
	return api, hooked, mngr
}

func TestFullResync(t *testing.T) {
	const instanceID = "i-1"

	t.Run("ENIUpdate", func(t *testing.T) {
		t.Parallel()
		api, hooked, mngr := newHookedInstancesManager(t)
		resynctest.ENIUpdate(t, mngr, hooked.setHook, instanceID, func() (string, *types.ENI, error) {
			eniID, eni, err := api.CreateNetworkInterface(context.Background(), 1, "vsw-1", []string{"sg-1"}, nil)
			if err != nil {
				return "", nil, err
			}
			return eniID, eni, api.AttachNetworkInterface(context.Background(), instanceID, eniID)
		})
	})

	t.Run("InstanceDelete", func(t *testing.T) {
		t.Parallel()
		_, hooked, mngr := newHookedInstancesManager(t)
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

type hookedInstanceAPI struct {
	AlibabaCloudAPI
	afterGetInstance func()
	hookCalled       atomic.Bool
}

func (h *hookedInstanceAPI) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	instance, err := h.AlibabaCloudAPI.GetInstance(ctx, vpcs, subnets, instanceID)
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
	)
	initialENI := &types.ENI{NetworkInterfaceID: eniID}
	newENI := &types.ENI{NetworkInterfaceID: "eni-2"}

	tests := []struct {
		name   string
		want   apimock.ENIMap
		update func(context.Context, *InstancesManager) error
	}{
		{
			name: "UpdateENI",
			want: apimock.ENIMap{eniID: initialENI, newENI.NetworkInterfaceID: newENI},
			update: func(_ context.Context, m *InstancesManager) error {
				m.UpdateENI(instanceID, newENI)
				return nil
			},
		},
		{
			name: "InstanceSync",
			want: apimock.ENIMap{eniID: initialENI, newENI.NetworkInterfaceID: newENI},
			update: func(ctx context.Context, m *InstancesManager) error {
				_, err := m.InstanceSync(ctx, instanceID)
				return err
			},
		},
		{
			name: "DeleteInstance",
			want: apimock.ENIMap{},
			update: func(_ context.Context, m *InstancesManager) error {
				m.DeleteInstance(instanceID)
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cloud := apimock.NewAPI(subnets, vpcs, securityGroups)
			cloud.UpdateENIs(map[string]apimock.ENIMap{instanceID: {eniID: initialENI}})
			hooked := &hookedInstanceAPI{AlibabaCloudAPI: cloud}
			manager := NewInstancesManager(hivetest.Logger(t), hooked)
			_, err := manager.Resync(t.Context())
			require.NoError(t, err)
			require.True(t, manager.HasInstance(instanceID))

			var updateErr error
			resynctest.RunDuringResync(t,
				instanceSyncResyncer{manager: manager, instanceID: instanceID},
				func(hook func()) { hooked.afterGetInstance = hook },
				func() error {
					// The partial sync has already captured initialENI. Change
					// the cloud now so its delayed response contains the older state.
					cloud.UpdateENIs(map[string]apimock.ENIMap{instanceID: test.want})
					return nil
				},
				func() { updateErr = test.update(t.Context(), manager) },
			)
			require.NoError(t, updateErr)

			// The old snapshot must not undo the ENI change or resurrect a
			// deleted instance after both operations finish.
			cached := apimock.ENIMap{}
			manager.ForeachInstance(instanceID, func(_, eniID string, iface ipamTypes.Interface) error {
				cached[eniID] = iface.(*types.ENI)
				return nil
			})
			require.Equal(t, test.want, cached)
			require.Equal(t, len(test.want) > 0, manager.HasInstance(instanceID))
		})
	}
}
