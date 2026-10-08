// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

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
