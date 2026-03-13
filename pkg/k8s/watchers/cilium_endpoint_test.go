// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

type testEndpointManager struct {
	endpoints map[string]*endpoint.Endpoint
}

func (m *testEndpointManager) LookupCEPName(namespacedName string) *endpoint.Endpoint {
	return m.endpoints[namespacedName]
}

func (m *testEndpointManager) GetEndpoints() []*endpoint.Endpoint {
	return nil
}

func (m *testEndpointManager) GetHostEndpoint() *endpoint.Endpoint {
	return nil
}

func (m *testEndpointManager) GetEndpointsByPodName(string) []*endpoint.Endpoint {
	return nil
}

func (m *testEndpointManager) UpdatePolicyMaps(context.Context, *sync.WaitGroup) *sync.WaitGroup {
	return nil
}

type testPolicyManager struct{}

func (m *testPolicyManager) TriggerPolicyUpdates(reason string) {}

type testWireguardConfig struct{}

func (m *testWireguardConfig) Enabled() bool { return false }

type testIPSecConfig struct{}

func (m *testIPSecConfig) Enabled() bool                                         { return false }
func (m *testIPSecConfig) UseCiliumInternalIP() bool                             { return false }
func (m *testIPSecConfig) DNSProxyInsecureSkipTransparentModeCheckEnabled() bool { return false }

type testIPCacheManager struct{}

func (m *testIPCacheManager) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (bool, error) {
	return false, nil
}

func (m *testIPCacheManager) LookupByIP(IP string) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}

func (m *testIPCacheManager) Delete(IP string, source source.Source) bool {
	return false
}

func (m *testIPCacheManager) DeleteOnMetadataMatch(ip string, source source.Source, namespace, name string) bool {
	return false
}

func (m *testIPCacheManager) UpsertMetadata(prefix cmtypes.PrefixCluster, src source.Source, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata) {
}

func (m *testIPCacheManager) RemoveLabelsExcluded(lbls labels.Labels, toExclude map[cmtypes.PrefixCluster]struct{}, resource ipcacheTypes.ResourceID) {
}

func newTestWatcher(t *testing.T, endpoints map[string]*endpoint.Endpoint) *K8sCiliumEndpointsWatcher {
	return &K8sCiliumEndpointsWatcher{
		logger:          hivetest.Logger(t),
		endpointManager: &testEndpointManager{endpoints: endpoints},
		policyManager:   &testPolicyManager{},
		ipcache:         &testIPCacheManager{},
		localNodeStore:  node.NewTestLocalNodeStore(node.LocalNode{Node: nodetypes.Node{Name: "test-node"}}),
		wgConfig:        &testWireguardConfig{},
		ipsecConfig:     &testIPSecConfig{},
	}
}

func newTestCiliumEndpoint(namespace, name, nodeIP, ipv4 string) *types.CiliumEndpoint {
	return &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Identity: &v2.EndpointIdentity{
			ID: 123,
		},
		Networking: &v2.EndpointNetworking{
			NodeIP: nodeIP,
			Addressing: []*v2.AddressPair{
				{IPV4: ipv4},
			},
		},
	}
}

func TestEndpointUpdated_RecordsMetricWhenLocalEndpointExists(t *testing.T) {
	watcher := newTestWatcher(t, map[string]*endpoint.Endpoint{
		"default/test-pod": {},
	})

	cep := newTestCiliumEndpoint("default", "test-pod", "192.168.1.1", "10.0.0.1")
	watcher.endpointUpdated(nil, cep)
}

func TestEndpointUpdated_SafeWhenNoLocalEndpoint(t *testing.T) {
	watcher := newTestWatcher(t, map[string]*endpoint.Endpoint{})

	cep := newTestCiliumEndpoint("default", "test-pod", "192.168.1.1", "10.0.0.1")
	watcher.endpointUpdated(nil, cep)
}

func TestEndpointUpdated_SkipsWhenNoNetworking(t *testing.T) {
	watcher := newTestWatcher(t, map[string]*endpoint.Endpoint{
		"default/test-pod": {},
	})

	cep := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Identity: &v2.EndpointIdentity{
			ID: 123,
		},
		Networking: nil,
	}

	watcher.endpointUpdated(nil, cep)
}
