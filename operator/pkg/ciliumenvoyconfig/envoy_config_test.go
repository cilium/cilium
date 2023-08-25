// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"testing"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func Test_getClusterResources(t *testing.T) {
	m := &Manager{}
	res, err := m.getClusterResources(&slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-service",
			Namespace: "dummy-namespace",
		},
	})
	require.NoError(t, err)

	require.Len(t, res, 1)

	cluster := &envoy_config_cluster_v3.Cluster{}
	err = proto.Unmarshal(res[0].Value, cluster)
	require.NoError(t, err)

	require.Equal(t, "dummy-namespace/dummy-service", cluster.Name)
	require.Equal(t, envoy_config_cluster_v3.Cluster_ROUND_ROBIN, cluster.LbPolicy)
	require.Equal(t, &envoy_config_cluster_v3.Cluster_Type{
		Type: envoy_config_cluster_v3.Cluster_EDS,
	}, cluster.ClusterDiscoveryType)
}

func Test_getRouteConfigurationResource(t *testing.T) {
	m := &Manager{}
	res, err := m.getRouteConfigurationResource(&slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-service",
			Namespace: "dummy-namespace",
		},
	})

	require.NoError(t, err)
	routeConfig := &envoy_config_route_v3.RouteConfiguration{}
	err = proto.Unmarshal(res.Value, routeConfig)
	require.NoError(t, err)

	require.Len(t, routeConfig.VirtualHosts, 1)
	require.Equal(t, "dummy-namespace/dummy-service", routeConfig.VirtualHosts[0].Name)
	require.Equal(t, []string{"*"}, routeConfig.VirtualHosts[0].Domains)
	require.Len(t, routeConfig.VirtualHosts[0].Routes, 1)
}

func Test_getListenerResource(t *testing.T) {
	m := &Manager{}
	res, err := m.getListenerResource(&slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-service",
			Namespace: "dummy-namespace",
		},
	})
	require.NoError(t, err)

	listener := &envoy_config_listener.Listener{}
	err = proto.Unmarshal(res.Value, listener)
	require.NoError(t, err)

	require.Len(t, listener.ListenerFilters, 1)
	require.Len(t, listener.FilterChains, 1)
	require.Len(t, listener.FilterChains[0].Filters, 1)
	require.IsType(t, &envoy_config_listener.Filter_TypedConfig{}, listener.FilterChains[0].Filters[0].ConfigType)
}
