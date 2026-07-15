// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"testing"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_upstream "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_getClusterResources(t *testing.T) {
	r := &ciliumEnvoyConfigReconciler{
		idleTimeoutSeconds:       60,
		maxRequestsPerConnection: 1,
	}
	res, err := r.getClusterResources(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
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

	protocolOptions := &envoy_config_upstream.HttpProtocolOptions{}
	require.NoError(t, cluster.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].UnmarshalTo(protocolOptions))
	require.Equal(t, int64(60), protocolOptions.CommonHttpProtocolOptions.IdleTimeout.Seconds)
	require.Equal(t, uint32(1), protocolOptions.CommonHttpProtocolOptions.MaxRequestsPerConnection.Value)
}

func Test_getRouteConfigurationResource(t *testing.T) {
	r := &ciliumEnvoyConfigReconciler{
		httpRetryCount:   3,
		httpRetryTimeout: 5,
	}
	res, err := r.getRouteConfigurationResource(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
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
	retryPolicy := routeConfig.VirtualHosts[0].Routes[0].GetRoute().GetRetryPolicy()
	require.NotNil(t, retryPolicy)
	require.Equal(t, "5xx", retryPolicy.GetRetryOn())
	require.Equal(t, uint32(3), retryPolicy.GetNumRetries().GetValue())
	require.Equal(t, int64(5), retryPolicy.GetPerTryTimeout().GetSeconds())
}

func Test_getListenerResource(t *testing.T) {
	r := &ciliumEnvoyConfigReconciler{}
	res, err := r.getListenerResource(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
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
