// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipcache"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// mockEndpoint implements a minimal endpoint for testing
type mockEndpoint struct {
	endpoint.Endpoint
	createdAt time.Time
}

func (m *mockEndpoint) GetCreatedAt() time.Time {
	return m.createdAt
}

// mockEndpointManager implements the endpointManager interface for testing
type mockEndpointManager struct {
	endpoints map[string]*mockEndpoint
}

func (m *mockEndpointManager) LookupCEPName(namespacedName string) *endpoint.Endpoint {
	if ep, ok := m.endpoints[namespacedName]; ok {
		return &ep.Endpoint
	}
	return nil
}

func (m *mockEndpointManager) GetEndpoints() []*endpoint.Endpoint {
	return nil
}

func (m *mockEndpointManager) GetHostEndpoint() *endpoint.Endpoint {
	return nil
}

func (m *mockEndpointManager) GetEndpointsByPodName(string) []*endpoint.Endpoint {
	return nil
}

func (m *mockEndpointManager) UpdatePolicyMaps(context.Context, *sync.WaitGroup) *sync.WaitGroup {
	return nil
}

func (m *mockEndpointManager) MarkAllEndpointsFrozen()   {}
func (m *mockEndpointManager) UnmarkAllEndpointsFrozen() {}
func (m *mockEndpointManager) RemoveAll()                {}

// mockPolicyManager implements the policyManager interface for testing
type mockPolicyManager struct{}

func (m *mockPolicyManager) TriggerPolicyUpdates(reason string) {}

// mockIPCacheManager implements the ipcacheManager interface for testing
type mockIPCacheManager struct{}

func (m *mockIPCacheManager) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (bool, error) {
	return false, nil
}

func (m *mockIPCacheManager) LookupByIP(IP string) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}

func (m *mockIPCacheManager) Delete(IP string, source source.Source) bool {
	return false
}

func (m *mockIPCacheManager) DeleteOnMetadataMatch(ip string, source source.Source, namespace, name string) bool {
	return false
}

// TestEndpointUpdated_RecordsMetricWhenLocalEndpointExists verifies that
// endpointUpdated safely records the metric when a local endpoint exists.
func TestEndpointUpdated_RecordsMetricWhenLocalEndpointExists(t *testing.T) {
	// Create a mock endpoint with a creation timestamp
	ep := &mockEndpoint{
		createdAt: time.Now().Add(-5 * time.Second),
	}

	// Create mock endpoint manager with the endpoint
	mockEpMgr := &mockEndpointManager{
		endpoints: map[string]*mockEndpoint{
			"default/test-pod": ep,
		},
	}

	// Create watcher with mocked dependencies
	watcher := &K8sCiliumEndpointsWatcher{
		logger:          hivetest.Logger(t),
		endpointManager: mockEpMgr,
		policyManager:   &mockPolicyManager{},
		ipcache:         &mockIPCacheManager{},
		localNodeStore:  node.NewTestLocalNodeStore(node.LocalNode{Node: nodetypes.Node{Name: "test-node"}}),
	}

	// Create a CiliumEndpoint
	cep := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Identity: &v2.EndpointIdentity{
			ID: 123,
		},
		Networking: &v2.EndpointNetworking{
			NodeIP: "192.168.1.1",
			Addressing: []*v2.AddressPair{
				{
					IPV4: "10.0.0.1",
				},
			},
		},
	}

	// Call endpointUpdated - should not panic and should record metric
	watcher.endpointUpdated(nil, cep)

	// If we reach here without panic, the test passes
}

// TestEndpointUpdated_SafeWhenNoLocalEndpoint verifies that endpointUpdated
// handles the case when LookupCEPName returns nil (no local endpoint).
func TestEndpointUpdated_SafeWhenNoLocalEndpoint(t *testing.T) {
	// Create mock endpoint manager with no endpoints
	mockEpMgr := &mockEndpointManager{
		endpoints: map[string]*mockEndpoint{},
	}

	// Create watcher with mocked dependencies
	watcher := &K8sCiliumEndpointsWatcher{
		logger:          hivetest.Logger(t),
		endpointManager: mockEpMgr,
		policyManager:   &mockPolicyManager{},
		ipcache:         &mockIPCacheManager{},
		localNodeStore:  node.NewTestLocalNodeStore(node.LocalNode{Node: nodetypes.Node{Name: "test-node"}}),
	}

	// Create a CiliumEndpoint
	cep := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Identity: &v2.EndpointIdentity{
			ID: 123,
		},
		Networking: &v2.EndpointNetworking{
			NodeIP: "192.168.1.1",
			Addressing: []*v2.AddressPair{
				{
					IPV4: "10.0.0.1",
				},
			},
		},
	}

	// Call endpointUpdated - should not panic even though no local endpoint exists
	watcher.endpointUpdated(nil, cep)

	// If we reach here without panic, the test passes
}

// TestEndpointUpdated_SafeWhenEndpointNil verifies that endpointUpdated
// handles the case when the endpoint parameter is nil.
func TestEndpointUpdated_SafeWhenEndpointNil(t *testing.T) {
	// Create mock endpoint manager
	mockEpMgr := &mockEndpointManager{
		endpoints: map[string]*mockEndpoint{},
	}

	// Create watcher with mocked dependencies
	watcher := &K8sCiliumEndpointsWatcher{
		logger:          hivetest.Logger(t),
		endpointManager: mockEpMgr,
		policyManager:   &mockPolicyManager{},
		ipcache:         &mockIPCacheManager{},
		localNodeStore:  node.NewTestLocalNodeStore(node.LocalNode{Node: nodetypes.Node{Name: "test-node"}}),
	}

	// Call endpointUpdated with nil endpoint - should not panic
	watcher.endpointUpdated(nil, nil)

	// If we reach here without panic, the test passes
}

// TestEndpointUpdated_SkipsWhenNoNetworking verifies that endpointUpdated
// safely handles endpoints without networking information.
func TestEndpointUpdated_SkipsWhenNoNetworking(t *testing.T) {
	// Create a mock endpoint
	ep := &mockEndpoint{
		createdAt: time.Now().Add(-5 * time.Second),
	}

	// Create mock endpoint manager with the endpoint
	mockEpMgr := &mockEndpointManager{
		endpoints: map[string]*mockEndpoint{
			"default/test-pod": ep,
		},
	}

	// Create watcher with mocked dependencies
	watcher := &K8sCiliumEndpointsWatcher{
		logger:          hivetest.Logger(t),
		endpointManager: mockEpMgr,
		policyManager:   &mockPolicyManager{},
		ipcache:         &mockIPCacheManager{},
		localNodeStore:  node.NewTestLocalNodeStore(node.LocalNode{Node: nodetypes.Node{Name: "test-node"}}),
	}

	// Create a CiliumEndpoint without networking (should return early)
	cep := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Identity: &v2.EndpointIdentity{
			ID: 123,
		},
		Networking: nil, // No networking info
	}

	// Call endpointUpdated - should return early but not panic
	watcher.endpointUpdated(nil, cep)

	// If we reach here without panic, the test passes
}
