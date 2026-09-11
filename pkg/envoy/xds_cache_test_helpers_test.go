// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"maps"
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

func cachedListeners(cache xdsnew.Cache, nodeID string) map[string]*envoy_config_listener.Listener {
	resources := publishedResources(cache, nodeID, typeurl.Listener)
	if len(resources) == 0 {
		return nil
	}
	listeners := make(map[string]*envoy_config_listener.Listener, len(resources))
	for name, resource := range resources {
		listeners[name] = resource.(*envoy_config_listener.Listener)
	}
	return listeners
}

func publishedResources(cache xdsnew.Cache, nodeID string, typeURL typeurl.Index) map[string]cache_types.Resource {
	snapshot, err := cache.GetSnapshot(nodeID)
	if err != nil {
		return nil
	}
	return snapshot.GetResources(typeURL.URL())
}

func cachedNetworkPolicies(cache xdsnew.Cache, nodeID string) map[string]*cilium.NetworkPolicy {
	return maps.Collect(cache.NetworkPolicies(nodeID))
}

func requireCachedResource(t testing.TB, cache xdsnew.Cache, nodeID, typeURL, name string) {
	t.Helper()
	typeIndex, supported := typeurl.FromURL(typeURL)
	require.True(t, supported)
	require.NotNil(t, cache.GetResource(nodeID, typeIndex, name))
}

func requireNoCachedResource(t testing.TB, cache xdsnew.Cache, nodeID, typeURL, name string) {
	t.Helper()
	typeIndex, supported := typeurl.FromURL(typeURL)
	require.True(t, supported)
	require.Nil(t, cache.GetResource(nodeID, typeIndex, name))
}

func cachedListener(t testing.TB, cache xdsnew.Cache, nodeID, name string) *envoy_config_listener.Listener {
	t.Helper()
	resource := cache.GetResource(nodeID, typeurl.Listener, name)
	listener, ok := resource.(*envoy_config_listener.Listener)
	require.True(t, ok)
	return listener
}

func cachedNetworkPolicy(t testing.TB, cache xdsnew.Cache, nodeID, name string) *cilium.NetworkPolicy {
	t.Helper()
	resource := cache.GetResource(nodeID, typeurl.NetworkPolicy, name)
	policy, ok := resource.(*cilium.NetworkPolicy)
	require.True(t, ok)
	return policy
}
