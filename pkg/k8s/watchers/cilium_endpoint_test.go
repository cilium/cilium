// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
)

func newCEPWatcherTest(t *testing.T) (*K8sCiliumEndpointsWatcher, *ipcache.IPCache) {
	t.Helper()

	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context: t.Context(),
		Logger:  hivetest.Logger(t),
	})
	t.Cleanup(func() {
		require.NoError(t, ipc.Shutdown())
	})

	return &K8sCiliumEndpointsWatcher{
		logger:         hivetest.Logger(t),
		policyManager:  &fakePolicyManager{},
		ipcache:        ipc,
		localNodeStore: node.NewTestLocalNodeStore(node.LocalNode{}),
		wgConfig:       fakewireguard.Config{},
		ipsecConfig:    fakeipsec.Config{},
	}, ipc
}

func newTestCEP(nodeIP string, ips ...string) *types.CiliumEndpoint {
	cep := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Namespace: "default",
			Name:      "echo",
		},
		Identity: &v2.EndpointIdentity{ID: 12345},
		Networking: &v2.EndpointNetworking{
			NodeIP: nodeIP,
		},
	}
	for _, ip := range ips {
		cep.Networking.Addressing = append(cep.Networking.Addressing, &v2.AddressPair{IPV4: ip})
	}
	return cep
}

// TestEndpointUpdatedInvalidNodeIPKeepsIPCache verifies that a CiliumEndpoint
// update that is rejected due to missing or invalid networking information
// does not remove the previously known IPs of the endpoint from the ipcache.
func TestEndpointUpdatedInvalidNodeIPKeepsIPCache(t *testing.T) {
	const podIP = "10.0.0.1"

	tests := []struct {
		name    string
		updated func() *types.CiliumEndpoint
	}{
		{
			name: "nil networking",
			updated: func() *types.CiliumEndpoint {
				cep := newTestCEP("", podIP)
				cep.Networking = nil
				return cep
			},
		},
		{
			name:    "empty node IP",
			updated: func() *types.CiliumEndpoint { return newTestCEP("", podIP) },
		},
		{
			name:    "unparseable node IP",
			updated: func() *types.CiliumEndpoint { return newTestCEP("not-an-ip", podIP) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher, ipc := newCEPWatcherTest(t)

			initial := newTestCEP("192.0.2.10", podIP)
			watcher.endpointUpdated(nil, initial)

			id, exists := ipc.LookupByIP(podIP)
			require.True(t, exists)
			require.Equal(t, identity.NumericIdentity(12345), id.ID)

			watcher.endpointUpdated(initial, tt.updated())

			id, exists = ipc.LookupByIP(podIP)
			require.True(t, exists, "ipcache entry must be preserved when the update is rejected")
			require.Equal(t, identity.NumericIdentity(12345), id.ID)
		})
	}
}

// TestEndpointUpdatedIPChangeRemovesStaleIP verifies that a valid update
// replacing the endpoint IP upserts the new IP and removes the stale one.
func TestEndpointUpdatedIPChangeRemovesStaleIP(t *testing.T) {
	const (
		oldIP = "10.0.0.1"
		newIP = "10.0.0.2"
	)

	watcher, ipc := newCEPWatcherTest(t)

	initial := newTestCEP("192.0.2.10", oldIP)
	watcher.endpointUpdated(nil, initial)
	_, exists := ipc.LookupByIP(oldIP)
	require.True(t, exists)

	watcher.endpointUpdated(initial, newTestCEP("192.0.2.10", newIP))

	_, exists = ipc.LookupByIP(oldIP)
	require.False(t, exists, "stale IP must be removed from ipcache")
	id, exists := ipc.LookupByIP(newIP)
	require.True(t, exists)
	require.Equal(t, identity.NumericIdentity(12345), id.ID)
}
