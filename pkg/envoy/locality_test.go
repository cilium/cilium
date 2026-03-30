// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	envoy_config_bootstrap "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/stretchr/testify/require"
)

func TestAppendEmbeddedLocalityBootstrap(t *testing.T) {
	bs := &envoy_config_bootstrap.Bootstrap{
		StaticResources: &envoy_config_bootstrap.Bootstrap_StaticResources{},
	}

	appendEmbeddedLocalityBootstrap(bs, 7, "zone-a")

	require.Equal(t, localityClusterName, bs.GetClusterManager().GetLocalClusterName())
	require.Equal(t, "zone-a", bs.GetNode().GetLocality().GetZone())
	require.Len(t, bs.GetStaticResources().GetClusters(), 1)

	cluster := bs.GetStaticResources().GetClusters()[0]
	require.Equal(t, localityClusterName, cluster.GetName())
	require.Equal(t, envoy_config_cluster.Cluster_EDS, cluster.GetType())
	require.Equal(t, CiliumXDSClusterName, cluster.GetEdsClusterConfig().GetEdsConfig().GetApiConfigSource().GetGrpcServices()[0].GetEnvoyGrpc().GetClusterName())
}
