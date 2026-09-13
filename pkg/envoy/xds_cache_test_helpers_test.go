// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"maps"
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/envoy/xdsnew"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

func cachedListeners(cache xdsnew.Cache, nodeID string) map[string]*envoy_config_listener.Listener {
	return maps.Collect(cache.Listeners(nodeID))
}

func cachedNetworkPolicies(cache xdsnew.Cache, nodeID string) map[string]*cilium.NetworkPolicy {
	return maps.Collect(cache.NetworkPolicies(nodeID))
}

func requireCachedResource(t testing.TB, cache xdsnew.Cache, nodeID, typeURL, name string) {
	t.Helper()
	typeIndex, supported := typeurl.FromURL(typeURL)
	require.True(t, supported)
	resource, exists := cache.GetResource(nodeID, typeIndex, name)
	require.True(t, exists)
	require.NotNil(t, resource)
}

func requireNoCachedResource(t testing.TB, cache xdsnew.Cache, nodeID, typeURL, name string) {
	t.Helper()
	typeIndex, supported := typeurl.FromURL(typeURL)
	require.True(t, supported)
	resource, exists := cache.GetResource(nodeID, typeIndex, name)
	require.False(t, exists)
	require.Nil(t, resource)
}

func cachedListener(t testing.TB, cache xdsnew.Cache, nodeID, name string) *envoy_config_listener.Listener {
	t.Helper()
	resource, exists := cache.GetResource(nodeID, typeurl.Listener, name)
	require.True(t, exists)
	listener, ok := resource.(*envoy_config_listener.Listener)
	require.True(t, ok)
	return listener
}

func cachedNetworkPolicy(t testing.TB, cache xdsnew.Cache, nodeID, name string) *cilium.NetworkPolicy {
	t.Helper()
	resource, exists := cache.GetResource(nodeID, typeurl.NetworkPolicy, name)
	require.True(t, exists)
	policy, ok := resource.(*cilium.NetworkPolicy)
	require.True(t, ok)
	return policy
}
