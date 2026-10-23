// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apiMock "github.com/cilium/cilium/pkg/aws/api/mock"
	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/ipam/resynctest"
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
