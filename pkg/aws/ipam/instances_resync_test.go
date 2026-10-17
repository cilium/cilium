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
	resynctest.RunDuringFullResync(t,
		func(hook func()) { hooked.afterGetInstances = hook },
		func(ctx context.Context) error {
			_, err := instances.Resync(ctx)
			return err
		},
		ec2Setup, cacheUpdate)
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

// TestFullResyncKeepsConcurrentInstanceDelete deletes an instance inside a full resync's fetch window.
func TestFullResyncKeepsConcurrentInstanceDelete(t *testing.T) {
	const instanceID = "i-testFullResyncKeepsConcurrentInstanceDelete"

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
	require.True(t, instances.HasInstance(instanceID))

	runDuringFullResync(t, hooked, instances,
		func() error { return nil },
		func() {
			instances.DeleteInstance(instanceID)
		})

	require.False(t, instances.HasInstance(instanceID))
}
