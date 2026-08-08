// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	config "github.com/cilium/cilium/pkg/envoy/config"
)

func TestGetHttpFilterChainProtoCONNECTPassThrough(t *testing.T) {
	chain := GetHttpFilterChainProto("test-cluster", false, false, "", xdsServerConfig{})
	require.Len(t, chain.Filters, 2)

	msg, err := chain.Filters[1].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	hcm, ok := msg.(*envoy_config_http.HttpConnectionManager)
	require.True(t, ok)

	require.Len(t, hcm.UpgradeConfigs, 2)
	assert.Equal(t, "CONNECT", hcm.UpgradeConfigs[1].UpgradeType)

	virtualHosts := hcm.GetRouteConfig().GetVirtualHosts()
	require.Len(t, virtualHosts, 1)
	routes := virtualHosts[0].GetRoutes()
	require.Len(t, routes, 3)
	connectRoute := routes[0]
	require.NotNil(t, connectRoute.GetMatch().GetConnectMatcher())
	assert.Equal(t, "test-cluster", connectRoute.GetRoute().GetCluster())
	assert.Empty(t, connectRoute.GetRoute().GetUpgradeConfigs(), "the upstream HTTP proxy must terminate CONNECT")
}

func TestGetListenerFilterADSMode(t *testing.T) {
	t.Run("ADS disabled: UseNphds not set", func(t *testing.T) {
		serverConfig := &xdsServerConfig{envoyXDSMode: config.EnvoyXDSModeSplit}
		lf := GetListenerFilter(true, false, 1234, -1, serverConfig)
		require.NotNil(t, lf)
		msg, err := lf.GetTypedConfig().UnmarshalNew()
		require.NoError(t, err)
		meta, ok := msg.(*cilium.BpfMetadata)
		require.True(t, ok)
		assert.Nil(t, meta.CiliumConfigSource) // not set for the legacy SotW mode
	})

	t.Run("ADS enabled: CiliumConfigSource set to ADS without NPHDS", func(t *testing.T) {
		serverConfig := &xdsServerConfig{envoyXDSMode: config.EnvoyXDSModeADS}
		lf := GetListenerFilter(true, false, 1234, -1, serverConfig)
		require.NotNil(t, lf)
		msg, err := lf.GetTypedConfig().UnmarshalNew()
		require.NoError(t, err)
		meta, ok := msg.(*cilium.BpfMetadata)
		require.True(t, ok)
		require.NotNil(t, meta.CiliumConfigSource)
		assert.NotNil(t, meta.CiliumConfigSource.GetAds(), "CiliumConfigSource should use ADS aggregated source")
		assert.Equal(t, envoy_config_core.ApiVersion_V3, meta.CiliumConfigSource.ResourceApiVersion)
	})
}
