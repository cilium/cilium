// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	n := &Node{}
	require.Equal(t, types.InterfaceAddressLimit, n.GetMaximumAllocatableIPv4())
}

const statusTestIDFormat = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/0/networkInterfaces/%s"

// SecurityGroup collates inversely to ID, so sorting by the wrong field shows up.
func newStatusTestInterfaces() []*types.AzureInterface {
	names := []string{"nic-c", "nic-a", "nic-b"}
	var ifaces []*types.AzureInterface
	for i, name := range names {
		ifaces = append(ifaces, &types.AzureInterface{
			ID:            fmt.Sprintf(statusTestIDFormat, name),
			SecurityGroup: fmt.Sprintf("sg-%d", len(names)-i),
			Addresses: []types.AzureAddress{
				{IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")), State: types.StateSucceeded},
				{IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")), State: types.StateSucceeded},
				{IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.3")), State: types.StateSucceeded},
			},
		})
	}
	return ifaces
}

// Repeated calls must produce an identical status, and it must match the copy
// the operator reads back from the apiserver, or
// ciliumNodeUpdateImplementation.UpdateStatus writes /status on every sync.
func TestPopulateStatusFieldsDeterministicOrder(t *testing.T) {
	node := newCapacityTestNode(t, newStatusTestInterfaces(), false)

	wantIDs := make([]string, 0, 3)
	for _, name := range []string{"nic-a", "nic-b", "nic-c"} {
		wantIDs = append(wantIDs, fmt.Sprintf(statusTestIDFormat, name))
	}

	// The sorts run in place, so they must operate on copies: the instance
	// cache is shared between nodes and only read locked.
	cached := map[string]*types.AzureInterface{}
	node.manager.instances.ForeachInterface("vm1", func(_, id string, obj ipamTypes.Interface) error {
		cached[id] = obj.(*types.AzureInterface).DeepCopy()
		return nil
	})
	require.Len(t, cached, 3)

	fromAPIServer := &v2.CiliumNode{}
	node.PopulateStatusFields(fromAPIServer)
	marshalled, err := json.Marshal(fromAPIServer)
	require.NoError(t, err)
	fromAPIServer = &v2.CiliumNode{}
	require.NoError(t, json.Unmarshal(marshalled, fromAPIServer))

	// ForeachInterface's map iteration order is randomized per call.
	for i := range 10 {
		k8sObj := &v2.CiliumNode{}
		node.PopulateStatusFields(k8sObj)

		got := k8sObj.Status.Azure.Interfaces
		ids := make([]string, 0, len(got))
		for _, iface := range got {
			ids = append(ids, iface.ID)

			addrs := make([]string, 0, len(iface.Addresses))
			for _, addr := range iface.Addresses {
				addrs = append(addrs, addr.IP.String())
			}
			require.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, addrs, "iteration %d", i)
		}
		require.Equal(t, wantIDs, ids, "iteration %d", i)

		require.True(t, fromAPIServer.Status.DeepEqual(&k8sObj.Status),
			"iteration %d: no-op sync differs from the apiserver copy, forcing a /status write", i)
	}

	node.manager.instances.ForeachInterface("vm1", func(_, id string, obj ipamTypes.Interface) error {
		require.True(t, cached[id].DeepEqual(obj.(*types.AzureInterface)),
			"cached interface %s mutated by PopulateStatusFields", id)
		return nil
	})
}

const (
	releaseTestVMSSNIC       = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/vm1/networkInterfaces/nic-vmss"
	releaseTestStandaloneNIC = "/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Network/networkInterfaces/nic-vm"
)

func newReleaseTestInterface(id, name, subnetID, primaryIP string, addresses ...types.AzureAddress) *types.AzureInterface {
	return &types.AzureInterface{
		ID:        id,
		Name:      name,
		IP:        iputil.AddrFrom(netip.MustParseAddr(primaryIP)),
		Subnet:    types.AzureSubnet{ID: subnetID},
		Addresses: addresses,
		State:     types.StateSucceeded,
	}
}

func releaseTestAddress(ip, state string) types.AzureAddress {
	return types.AzureAddress{IP: iputil.AddrFrom(netip.MustParseAddr(ip)), State: state}
}

func releaseTestPrefixes(cidrs ...string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, c := range cidrs {
		prefixes = append(prefixes, netip.MustParsePrefix(c))
	}
	return prefixes
}

func TestPrepareCIDRRelease(t *testing.T) {
	tests := []struct {
		name          string
		ifaces        []*types.AzureInterface
		usePrimary    bool
		noInstanceID  bool
		interfaceName string
		released      []string
		wantAttached  []string
		wantActions   map[string]nodemanager.ReleaseAction
	}{
		{
			name: "primary excluded without usePrimary",
			ifaces: []*types.AzureInterface{
				newReleaseTestInterface(releaseTestVMSSNIC, "nic-vmss", "subnet-1", "10.0.0.4",
					releaseTestAddress("10.0.0.5", types.StateSucceeded)),
			},
			released:     []string{"10.0.0.4/32", "10.0.0.5/32"},
			wantAttached: []string{"10.0.0.5/32"},
			wantActions: map[string]nodemanager.ReleaseAction{
				releaseTestVMSSNIC: {InterfaceID: releaseTestVMSSNIC, PoolID: "subnet-1", CIDRsToRelease: releaseTestPrefixes("10.0.0.5/32")},
			},
		},
		{
			name: "primary excluded with usePrimary",
			ifaces: []*types.AzureInterface{
				newReleaseTestInterface(releaseTestVMSSNIC, "nic-vmss", "subnet-1", "10.0.0.4",
					releaseTestAddress("10.0.0.4", types.StateSucceeded),
					releaseTestAddress("10.0.0.5", types.StateSucceeded)),
			},
			usePrimary:   true,
			released:     []string{"10.0.0.4/32", "10.0.0.5/32"},
			wantAttached: []string{"10.0.0.5/32"},
			wantActions: map[string]nodemanager.ReleaseAction{
				releaseTestVMSSNIC: {InterfaceID: releaseTestVMSSNIC, PoolID: "subnet-1", CIDRsToRelease: releaseTestPrefixes("10.0.0.5/32")},
			},
		},
		{
			name: "non-succeeded attached but not released, IPv6 skipped",
			ifaces: []*types.AzureInterface{
				newReleaseTestInterface(releaseTestVMSSNIC, "nic-vmss", "subnet-1", "10.0.0.4",
					releaseTestAddress("10.0.0.5", types.StateSucceeded),
					releaseTestAddress("10.0.0.6", "deleting"),
					releaseTestAddress("fd00::5", types.StateSucceeded),
					releaseTestAddress("10.0.0.7", types.StateSucceeded)),
			},
			released:     []string{"10.0.0.6/32", "fd00::5/128", "10.0.0.7/32"},
			wantAttached: []string{"10.0.0.5/32", "10.0.0.6/32", "10.0.0.7/32"},
			wantActions: map[string]nodemanager.ReleaseAction{
				releaseTestVMSSNIC: {InterfaceID: releaseTestVMSSNIC, PoolID: "subnet-1", CIDRsToRelease: releaseTestPrefixes("10.0.0.7/32")},
			},
		},
		{
			name: "updating attached but not released",
			ifaces: []*types.AzureInterface{
				newReleaseTestInterface(releaseTestVMSSNIC, "nic-vmss", "subnet-1", "10.0.0.4",
					releaseTestAddress("10.0.0.5", types.StateUpdating),
					releaseTestAddress("10.0.0.6", types.StateSucceeded)),
			},
			released:     []string{"10.0.0.5/32", "10.0.0.6/32"},
			wantAttached: []string{"10.0.0.5/32", "10.0.0.6/32"},
			wantActions: map[string]nodemanager.ReleaseAction{
				releaseTestVMSSNIC: {InterfaceID: releaseTestVMSSNIC, PoolID: "subnet-1", CIDRsToRelease: releaseTestPrefixes("10.0.0.6/32")},
			},
		},
		{
			name: "two interfaces give two actions",
			ifaces: []*types.AzureInterface{
				newReleaseTestInterface(releaseTestVMSSNIC, "nic-vmss", "subnet-1", "10.0.0.4",
					releaseTestAddress("10.0.0.5", types.StateSucceeded),
					releaseTestAddress("10.0.0.6", types.StateSucceeded)),
				newReleaseTestInterface(releaseTestStandaloneNIC, "nic-vm", "subnet-2", "10.1.0.4",
					releaseTestAddress("10.1.0.5", types.StateSucceeded)),
			},
			released:     []string{"10.0.0.5/32", "10.0.0.6/32", "10.1.0.5/32"},
			wantAttached: []string{"10.0.0.5/32", "10.0.0.6/32", "10.1.0.5/32"},
			wantActions: map[string]nodemanager.ReleaseAction{
				releaseTestVMSSNIC:       {InterfaceID: releaseTestVMSSNIC, PoolID: "subnet-1", CIDRsToRelease: releaseTestPrefixes("10.0.0.5/32", "10.0.0.6/32")},
				releaseTestStandaloneNIC: {InterfaceID: releaseTestStandaloneNIC, PoolID: "subnet-2", CIDRsToRelease: releaseTestPrefixes("10.1.0.5/32")},
			},
		},
		{
			name: "unselected interface attached but not released",
			ifaces: []*types.AzureInterface{
				newReleaseTestInterface(releaseTestVMSSNIC, "nic-vmss", "subnet-1", "10.0.0.4",
					releaseTestAddress("10.0.0.5", types.StateSucceeded)),
				newReleaseTestInterface(releaseTestStandaloneNIC, "nic-vm", "subnet-2", "10.1.0.4",
					releaseTestAddress("10.1.0.5", types.StateSucceeded)),
			},
			interfaceName: "nic-vmss",
			released:      []string{"10.0.0.5/32", "10.1.0.5/32"},
			wantAttached:  []string{"10.0.0.5/32", "10.1.0.5/32"},
			wantActions: map[string]nodemanager.ReleaseAction{
				releaseTestVMSSNIC: {InterfaceID: releaseTestVMSSNIC, PoolID: "subnet-1", CIDRsToRelease: releaseTestPrefixes("10.0.0.5/32")},
			},
		},
		{
			name: "nothing releasable",
			ifaces: []*types.AzureInterface{
				newReleaseTestInterface(releaseTestVMSSNIC, "nic-vmss", "subnet-1", "10.0.0.4",
					releaseTestAddress("10.0.0.6", "failed")),
			},
			released:     []string{"10.0.0.4/32", "10.0.0.6/32"},
			wantAttached: []string{"10.0.0.6/32"},
			wantActions:  map[string]nodemanager.ReleaseAction{},
		},
		{
			name: "no instance ID",
			ifaces: []*types.AzureInterface{
				newReleaseTestInterface(releaseTestVMSSNIC, "nic-vmss", "subnet-1", "10.0.0.4",
					releaseTestAddress("10.0.0.5", types.StateSucceeded)),
			},
			noInstanceID: true,
			released:     []string{"10.0.0.5/32"},
			wantActions:  map[string]nodemanager.ReleaseAction{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := newCapacityTestNode(t, test.ifaces, test.usePrimary)
			node.k8sObj.Spec.Azure.InterfaceName = test.interfaceName
			if test.noInstanceID {
				node.instanceID = ""
			}

			require.ElementsMatch(t, releaseTestPrefixes(test.wantAttached...), node.GetAttachedCIDRs())

			actions := map[string]nodemanager.ReleaseAction{}
			for _, action := range node.PrepareCIDRRelease(releaseTestPrefixes(test.released...)) {
				actions[action.InterfaceID] = *action
			}
			require.Equal(t, test.wantActions, actions)
		})
	}
}

func TestReleaseCIDRs(t *testing.T) {
	tests := []struct {
		name        string
		interfaceID string
		mockError   apimock.Operation
		wantErr     bool
	}{
		{name: "VMSS interface", interfaceID: releaseTestVMSSNIC},
		{name: "standalone interface", interfaceID: releaseTestStandaloneNIC},
		{name: "VMSS API error", interfaceID: releaseTestVMSSNIC, mockError: apimock.UnassignPrivateIpAddressesVMSS, wantErr: true},
		{name: "standalone API error", interfaceID: releaseTestStandaloneNIC, mockError: apimock.UnassignPrivateIpAddressesVM, wantErr: true},
		{name: "unknown interface", interfaceID: "unknown", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ifaces := []*types.AzureInterface{
				newReleaseTestInterface(releaseTestVMSSNIC, "nic-vmss", "subnet-1", "10.0.0.4",
					releaseTestAddress("10.0.0.5", types.StateSucceeded),
					releaseTestAddress("10.0.0.6", types.StateSucceeded),
					releaseTestAddress("10.0.0.7", types.StateSucceeded)),
				newReleaseTestInterface(releaseTestStandaloneNIC, "nic-vm", "subnet-1", "10.0.0.8",
					releaseTestAddress("10.0.0.5", types.StateSucceeded),
					releaseTestAddress("10.0.0.6", types.StateSucceeded),
					releaseTestAddress("10.0.0.7", types.StateSucceeded)),
			}
			node := newCapacityTestNode(t, ifaces, false)
			api := apimock.NewAPI(nil)
			api.UpdateInstances(node.manager.instances.DeepCopy())
			if test.mockError != 0 {
				api.SetMockError(test.mockError, errors.New("mock error"))
			}
			node.manager.api = api

			cidrs := releaseTestPrefixes("10.0.0.5/32", "10.0.0.6/32")
			released, err := node.ReleaseCIDRs(t.Context(), &nodemanager.ReleaseAction{
				InterfaceID:    test.interfaceID,
				PoolID:         "subnet-1",
				CIDRsToRelease: cidrs,
			})

			want := map[string][]string{
				releaseTestVMSSNIC:       {"10.0.0.5", "10.0.0.6", "10.0.0.7"},
				releaseTestStandaloneNIC: {"10.0.0.5", "10.0.0.6", "10.0.0.7"},
			}
			if test.wantErr {
				require.Error(t, err)
				require.Nil(t, released)
			} else {
				require.NoError(t, err)
				require.Equal(t, cidrs, released)
				want[test.interfaceID] = []string{"10.0.0.7"}
			}

			got := map[string][]string{}
			node.manager.instances.ForeachInterface("vm1", func(_, id string, obj ipamTypes.Interface) error {
				for _, addr := range obj.(*types.AzureInterface).Addresses {
					got[id] = append(got[id], addr.IP.String())
				}
				return nil
			})
			require.Equal(t, want, got)
		})
	}
}

func TestPrepareCIDRReleaseBeforeUpdatedNode(t *testing.T) {
	m := ipamTypes.NewInstanceMap()
	m.Update("vm1", newReleaseTestInterface(releaseTestVMSSNIC, "nic-vmss", "subnet-1", "10.0.0.4",
		releaseTestAddress("10.0.0.5", types.StateSucceeded)))
	m.Update("vm1", newReleaseTestInterface(releaseTestStandaloneNIC, "nic-vm", "subnet-2", "10.1.0.4",
		releaseTestAddress("10.1.0.5", types.StateSucceeded)))
	manager := &InstancesManager{instances: m, api: apimock.NewAPI(nil)}
	obj := &v2.CiliumNode{
		Spec: v2.NodeSpec{
			InstanceID: "vm1",
			Azure:      types.AzureSpec{InterfaceName: "nic-vmss"},
		},
	}

	node := manager.CreateNode(obj, nil).(*Node)
	actions := node.PrepareCIDRRelease(releaseTestPrefixes("10.0.0.5/32", "10.1.0.5/32"))
	require.Len(t, actions, 1)
	require.Equal(t, releaseTestPrefixes("10.0.0.5/32"), actions[0].CIDRsToRelease)
}

func TestNodeConcurrentUpdatedNode(t *testing.T) {
	m := ipamTypes.NewInstanceMap()
	m.Update("vm1", newReleaseTestInterface(releaseTestVMSSNIC, "nic-vmss", "subnet-1", "10.0.0.4",
		releaseTestAddress("10.0.0.5", types.StateSucceeded)))
	manager := &InstancesManager{instances: m, api: apimock.NewAPI(nil)}
	newObj := func() *v2.CiliumNode {
		return &v2.CiliumNode{
			Spec: v2.NodeSpec{
				InstanceID: "vm1",
				Azure:      types.AzureSpec{InterfaceName: "nic-vmss"},
			},
		}
	}
	node := manager.CreateNode(newObj(), nil).(*Node)
	logger := hivetest.Logger(t)

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			node.UpdatedNode(newObj())
		}
	})
	wg.Go(func() {
		for range 100 {
			_, _, err := node.ResyncInterfacesAndIPs(t.Context(), logger)
			require.NoError(t, err)
		}
	})
	for range 100 {
		_, err := node.PrepareIPAllocation(logger)
		require.NoError(t, err)
		node.GetAttachedCIDRs()
		node.PrepareCIDRRelease(releaseTestPrefixes("10.0.0.5/32"))
		_, err = node.AllocateStaticIP(t.Context(), nil)
		require.NoError(t, err)
	}
	wg.Wait()
}
