// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apimock "github.com/cilium/cilium/pkg/alibabacloud/api/mock"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/ipam/resynctest"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
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

func newHookedInstancesManager(t *testing.T) (*apimock.API, *hookedAPI, *InstancesManager) {
	api := apimock.NewAPI(subnets, vpcs, securityGroups)
	api.UpdateENIs(primaryENIs)
	hooked := &hookedAPI{AlibabaCloudAPI: api}
	mngr := NewInstancesManager(hivetest.Logger(t), hooked)
	_, err := mngr.Resync(t.Context())
	require.NoError(t, err)
	return api, hooked, mngr
}

// runDuringFullResync runs ecsSetup and then cacheUpdate inside the ECS fetch window of a full resync.
func runDuringFullResync(t *testing.T, hooked *hookedAPI, mngr *InstancesManager, ecsSetup func() error, cacheUpdate func()) {
	t.Helper()
	resynctest.RunDuringFullResync(t,
		func(hook func()) { hooked.afterGetInstances = hook },
		func(ctx context.Context) error {
			_, err := mngr.Resync(ctx)
			return err
		},
		ecsSetup, cacheUpdate)
}

func cachedENIIDs(m *InstancesManager, instanceID string) (ids []string) {
	m.ForeachInstance(instanceID, func(_, ifaceID string, _ ipamTypes.Interface) error {
		ids = append(ids, ifaceID)
		return nil
	})
	return ids
}

// TestFullResyncKeepsConcurrentENIUpdate attaches an ENI inside a full resync's fetch window.
func TestFullResyncKeepsConcurrentENIUpdate(t *testing.T) {
	const instanceID = "i-1"

	api, hooked, mngr := newHookedInstancesManager(t)
	before := cachedENIIDs(mngr, instanceID)
	require.NotEmpty(t, before)

	var createdENI string
	var createdIface *types.ENI
	runDuringFullResync(t, hooked, mngr,
		func() (err error) {
			createdENI, createdIface, err = api.CreateNetworkInterface(context.Background(), 1, "vsw-1", []string{"sg-1"}, nil)
			if err != nil {
				return err
			}
			return api.AttachNetworkInterface(context.Background(), instanceID, createdENI)
		},
		func() {
			mngr.UpdateENI(instanceID, createdIface)
		})

	require.ElementsMatch(t, append(before, createdENI), cachedENIIDs(mngr, instanceID))
}
