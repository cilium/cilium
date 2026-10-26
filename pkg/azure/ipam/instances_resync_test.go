// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/ipam/resynctest"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/time"
)

// hookedAPI calls afterListAllNetworkInterfaces while a full resync holds its Azure snapshot.
type hookedAPI struct {
	AzureAPI
	afterListAllNetworkInterfaces func()
}

func (h *hookedAPI) ListAllNetworkInterfaces(ctx context.Context) ([]*armnetwork.Interface, error) {
	interfaces, err := h.AzureAPI.ListAllNetworkInterfaces(ctx)
	if h.afterListAllNetworkInterfaces != nil {
		h.afterListAllNetworkInterfaces()
	}
	return interfaces, err
}

func (h *hookedAPI) setHook(hook func()) {
	h.afterListAllNetworkInterfaces = hook
}

func TestFullResync(t *testing.T) {
	t.Run("InstanceDelete", func(t *testing.T) {
		t.Parallel()
		api := apimock.NewAPI(subnets)
		hooked := &hookedAPI{AzureAPI: api}
		mngr := NewInstancesManager(hivetest.Logger(t), hooked, false)
		iteration1(t, api, mngr)
		resynctest.InstanceDelete(t, mngr, hooked.setHook, "i-1")
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
	AzureAPI
	afterParseInstance func()
	hookCalled         atomic.Bool
}

func (h *hookedInstanceAPI) ParseInterfacesIntoInstance(networkInterfaces []*armnetwork.Interface, subnets ipamTypes.SubnetMap) *ipamTypes.Instance {
	instance := h.AzureAPI.ParseInterfacesIntoInstance(networkInterfaces, subnets)
	// The mock captures cloud state during parsing, so hold the snapshot here.
	// Only delay the first snapshot so a concurrent InstanceSync can proceed.
	if h.afterParseInstance != nil && h.hookCalled.CompareAndSwap(false, true) {
		h.afterParseInstance()
	}
	return instance
}

func TestInstanceSyncPreservesConcurrentCacheChanges(t *testing.T) {
	const instanceID = "i-partial-sync"
	initialInterface := &types.AzureInterface{ID: "nic-1"}
	newInterface := &types.AzureInterface{ID: "nic-2"}

	tests := []struct {
		name   string
		want   map[string]*types.AzureInterface
		update func(context.Context, *InstancesManager) error
	}{
		{
			name: "InstanceSync",
			want: map[string]*types.AzureInterface{initialInterface.ID: initialInterface, newInterface.ID: newInterface},
			update: func(ctx context.Context, m *InstancesManager) error {
				_, err := m.InstanceSync(ctx, instanceID)
				return err
			},
		},
		{
			name: "DeleteInstance",
			want: map[string]*types.AzureInterface{},
			update: func(_ context.Context, m *InstancesManager) error {
				m.DeleteInstance(instanceID)
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cloud := apimock.NewAPI(subnets)
			initial := ipamTypes.NewInstanceMap()
			initial.Update(instanceID, initialInterface)
			cloud.UpdateInstances(initial)
			hooked := &hookedInstanceAPI{AzureAPI: cloud}
			manager := NewInstancesManager(hivetest.Logger(t), hooked, false)
			_, err := manager.Resync(t.Context())
			require.NoError(t, err)
			require.True(t, manager.HasInstance(instanceID))

			var updateErr error
			resynctest.RunDuringResync(t,
				instanceSyncResyncer{manager: manager, instanceID: instanceID},
				func(hook func()) { hooked.afterParseInstance = hook },
				func() error {
					// The partial sync has already captured initialInterface.
					// Change the cloud while that older snapshot is held.
					updated := ipamTypes.NewInstanceMap()
					for _, iface := range test.want {
						updated.Update(instanceID, iface)
					}
					cloud.UpdateInstances(updated)
					return nil
				},
				func() { updateErr = test.update(t.Context(), manager) },
			)
			require.NoError(t, updateErr)

			// The old snapshot must not undo the newer refresh or resurrect
			// a deleted instance after both operations finish.
			cached := map[string]*types.AzureInterface{}
			manager.mutex.RLock()
			manager.instances.ForeachInterface(instanceID, func(_, interfaceID string, iface ipamTypes.Interface) error {
				cached[interfaceID] = iface.(*types.AzureInterface)
				return nil
			})
			manager.mutex.RUnlock()
			require.Equal(t, test.want, cached)
			require.Equal(t, len(test.want) > 0, manager.HasInstance(instanceID))
		})
	}
}
