// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	envoy_config_bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/envoy/config"
)

func TestAppendEmbeddedLocalityBootstrap(t *testing.T) {
	tests := []struct {
		name      string
		xdsMode   string
		assertEDS func(t *testing.T, edsConfig *corev3.ConfigSource)
	}{
		{
			name:    "split",
			xdsMode: config.EnvoyXDSModeSplit,
			assertEDS: func(t *testing.T, edsConfig *corev3.ConfigSource) {
				apiConfigSource := edsConfig.GetApiConfigSource()
				require.NotNil(t, apiConfigSource)
				require.NotEmpty(t, apiConfigSource.GetGrpcServices())
				require.Equal(t, CiliumXDSClusterName, apiConfigSource.GetGrpcServices()[0].GetEnvoyGrpc().GetClusterName())
				require.Nil(t, edsConfig.GetAds())
			},
		},
		{
			name:    "ads",
			xdsMode: config.EnvoyXDSModeADS,
			assertEDS: func(t *testing.T, edsConfig *corev3.ConfigSource) {
				require.NotNil(t, edsConfig.GetAds())
				require.Nil(t, edsConfig.GetApiConfigSource())
			},
		},
		{
			name:    "strict-ads",
			xdsMode: config.EnvoyXDSModeStrictADS,
			assertEDS: func(t *testing.T, edsConfig *corev3.ConfigSource) {
				require.NotNil(t, edsConfig.GetAds())
				require.Nil(t, edsConfig.GetApiConfigSource())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetXDSMode(tt.xdsMode)
			t.Cleanup(func() { SetXDSMode("") })

			bs := &envoy_config_bootstrap.Bootstrap{
				StaticResources: &envoy_config_bootstrap.Bootstrap_StaticResources{},
			}

			appendEmbeddedLocalityBootstrap(bs, 7, "zone-a")

			require.Equal(t, LocalityClusterName, bs.GetClusterManager().GetLocalClusterName())
			require.Equal(t, "zone-a", bs.GetNode().GetLocality().GetZone())
			require.Len(t, bs.GetStaticResources().GetClusters(), 1)

			cluster := bs.GetStaticResources().GetClusters()[0]
			require.Equal(t, LocalityClusterName, cluster.GetName())
			require.Equal(t, envoy_config_cluster.Cluster_EDS, cluster.GetType())
			require.Equal(t, LocalityClusterName, cluster.GetEdsClusterConfig().GetServiceName())

			tt.assertEDS(t, cluster.GetEdsClusterConfig().GetEdsConfig())
		})
	}
}
