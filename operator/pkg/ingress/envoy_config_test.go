// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package ingress

import (
	"context"
	"testing"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_extensions_filters_network_http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func Test_getBackendServices(t *testing.T) {
	services := getBackendServices(baseIngress.DeepCopy())
	assert.Len(t, services, 3)
	assert.Equal(t, services, []*v2alpha1.Service{
		{
			Name:      "another-dummy-backend",
			Namespace: "dummy-namespace",
		},
		{
			Name:      "default-backend",
			Namespace: "dummy-namespace",
		},
		{
			Name:      "dummy-backend",
			Namespace: "dummy-namespace",
		},
	})
}

func Test_getListenerResource(t *testing.T) {
	t.Run("with https enforcement", func(t *testing.T) {
		res, err := getListenerResource(fakeClient(), baseIngress.DeepCopy(), true)
		require.NoError(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.NoError(t, err)

		require.Len(t, listener.ListenerFilters, 1)
		require.Len(t, listener.FilterChains, 2)
		require.Len(t, listener.FilterChains[0].Filters, 1)
		require.IsType(t, &envoy_config_listener.Filter_TypedConfig{}, listener.FilterChains[0].Filters[0].ConfigType)

		// check for connection manager
		redirectConnectionManager := &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager{}
		err = proto.Unmarshal(listener.FilterChains[0].Filters[0].ConfigType.(*envoy_config_listener.Filter_TypedConfig).TypedConfig.Value, redirectConnectionManager)
		require.NoError(t, err)

		require.Equal(t, "cilium-ingress-dummy-namespace-dummy-ingress", redirectConnectionManager.StatPrefix)
		require.Equal(t, "cilium-ingress-dummy-namespace-dummy-ingress_redirect", redirectConnectionManager.GetRds().RouteConfigName)

		httpConnectionManager := &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager{}
		err = proto.Unmarshal(listener.FilterChains[1].Filters[0].ConfigType.(*envoy_config_listener.Filter_TypedConfig).TypedConfig.Value, httpConnectionManager)
		require.NoError(t, err)

		require.Equal(t, "cilium-ingress-dummy-namespace-dummy-ingress", httpConnectionManager.StatPrefix)
		require.Equal(t, "cilium-ingress-dummy-namespace-dummy-ingress_route", httpConnectionManager.GetRds().RouteConfigName)

		// check TLS configuration
		require.Equal(t, "envoy.transport_sockets.tls", listener.FilterChains[1].TransportSocket.Name)
		require.IsType(t, &envoy_config_core_v3.TransportSocket_TypedConfig{}, listener.FilterChains[1].TransportSocket.ConfigType)

		downStreamTLS := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{}
		err = proto.Unmarshal(listener.FilterChains[1].TransportSocket.ConfigType.(*envoy_config_core_v3.TransportSocket_TypedConfig).TypedConfig.Value, downStreamTLS)
		require.NoError(t, err)

		require.Len(t, downStreamTLS.CommonTlsContext.TlsCertificates, 1)
		require.Equal(t, "very-secure-key", downStreamTLS.CommonTlsContext.TlsCertificates[0].PrivateKey.GetInlineString())
		require.Equal(t, "very-secure-cert", downStreamTLS.CommonTlsContext.TlsCertificates[0].CertificateChain.GetInlineString())
	})

	t.Run("without https enforcment", func(t *testing.T) {
		res, err := getListenerResource(fakeClient(), baseIngress.DeepCopy(), false)
		require.NoError(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.NoError(t, err)

		require.Len(t, listener.ListenerFilters, 1)
		require.Len(t, listener.FilterChains, 2)
		require.Len(t, listener.FilterChains[0].Filters, 1)
		require.IsType(t, &envoy_config_listener.Filter_TypedConfig{}, listener.FilterChains[0].Filters[0].ConfigType)

		// check for connection managers
		// http connection manager
		require.Equal(t, "raw_buffer", listener.FilterChains[0].FilterChainMatch.TransportProtocol)
		httpConnectionManager := &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager{}
		err = proto.Unmarshal(listener.FilterChains[0].Filters[0].ConfigType.(*envoy_config_listener.Filter_TypedConfig).TypedConfig.Value, httpConnectionManager)
		require.NoError(t, err)

		require.Equal(t, "cilium-ingress-dummy-namespace-dummy-ingress", httpConnectionManager.StatPrefix)
		require.Equal(t, "cilium-ingress-dummy-namespace-dummy-ingress_route", httpConnectionManager.GetRds().RouteConfigName)

		// https connection manager
		require.Equal(t, "tls", listener.FilterChains[1].FilterChainMatch.TransportProtocol)
		httpsConnectionManager := &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager{}
		err = proto.Unmarshal(listener.FilterChains[1].Filters[0].ConfigType.(*envoy_config_listener.Filter_TypedConfig).TypedConfig.Value, httpsConnectionManager)
		require.NoError(t, err)

		require.Equal(t, "cilium-ingress-dummy-namespace-dummy-ingress", httpsConnectionManager.StatPrefix)
		require.Equal(t, "cilium-ingress-dummy-namespace-dummy-ingress_route", httpsConnectionManager.GetRds().RouteConfigName)

		// check TLS configuration
		require.Equal(t, "envoy.transport_sockets.tls", listener.FilterChains[1].TransportSocket.Name)
		require.IsType(t, &envoy_config_core_v3.TransportSocket_TypedConfig{}, listener.FilterChains[1].TransportSocket.ConfigType)

		downStreamTLS := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{}
		err = proto.Unmarshal(listener.FilterChains[1].TransportSocket.ConfigType.(*envoy_config_core_v3.TransportSocket_TypedConfig).TypedConfig.Value, downStreamTLS)
		require.NoError(t, err)

		require.Len(t, downStreamTLS.CommonTlsContext.TlsCertificates, 1)
		require.Equal(t, "very-secure-key", downStreamTLS.CommonTlsContext.TlsCertificates[0].PrivateKey.GetInlineString())
		require.Equal(t, "very-secure-cert", downStreamTLS.CommonTlsContext.TlsCertificates[0].CertificateChain.GetInlineString())
	})
}

func Test_getRouteConfigurationResource(t *testing.T) {
	res, err := getRouteConfigurationResource(baseIngress.DeepCopy())

	require.NoError(t, err)
	routeConfig := &envoy_config_route_v3.RouteConfiguration{}
	err = proto.Unmarshal(res.Value, routeConfig)
	require.NoError(t, err)

	require.Len(t, routeConfig.VirtualHosts, 2)
	require.Equal(t, "*", routeConfig.VirtualHosts[0].Name)
	require.Equal(t, []string{"*"}, routeConfig.VirtualHosts[0].Domains)
	require.Len(t, routeConfig.VirtualHosts[0].Routes, 2)
	require.Len(t, routeConfig.VirtualHosts[0].Routes[0].Match.GetHeaders(), 0)

	require.Equal(t, "default-backend", routeConfig.VirtualHosts[1].Name)
	require.Equal(t, []string{"*"}, routeConfig.VirtualHosts[1].Domains)
	require.Len(t, routeConfig.VirtualHosts[1].Routes, 1)

	require.Equal(t, "/dummy-path", routeConfig.VirtualHosts[0].Routes[0].Match.GetPath())
	require.Equal(t, "/another-dummy-path(/.*)?$", routeConfig.VirtualHosts[0].Routes[1].Match.GetSafeRegex().GetRegex())
	require.Equal(t, "/", routeConfig.VirtualHosts[1].Routes[0].Match.GetPrefix())
	require.Len(t, routeConfig.VirtualHosts[1].Routes[0].Match.GetHeaders(), 0)

	clusters := []string{routeConfig.VirtualHosts[0].Routes[0].GetRoute().GetCluster(), routeConfig.VirtualHosts[0].Routes[1].GetRoute().GetCluster()}
	require.Contains(t, clusters, "dummy-namespace/dummy-backend")
	require.Contains(t, clusters, "dummy-namespace/another-dummy-backend")
}

func Test_getRedirectConfigurationResource(t *testing.T) {
	res, err := getRedirectRouteConfigurationResource(baseIngress.DeepCopy())

	require.NoError(t, err)
	routeConfig := &envoy_config_route_v3.RouteConfiguration{}
	err = proto.Unmarshal(res.Value, routeConfig)
	require.NoError(t, err)

	require.Len(t, routeConfig.VirtualHosts, 1)
	require.Equal(t, "default-redirect", routeConfig.VirtualHosts[0].Name)
	require.Equal(t, []string{"*"}, routeConfig.VirtualHosts[0].Domains)
	require.Len(t, routeConfig.VirtualHosts[0].Routes, 1)

	require.Equal(t, true, routeConfig.VirtualHosts[0].Routes[0].GetRedirect().GetHttpsRedirect())
	require.Equal(t, envoy_config_route_v3.RedirectAction_PERMANENT_REDIRECT, routeConfig.VirtualHosts[0].Routes[0].GetRedirect().GetResponseCode())
}

func Test_getClusterResources(t *testing.T) {
	res, err := getClusterResources(getBackendServices(baseIngress.DeepCopy()))
	require.NoError(t, err)

	require.Len(t, res, 3)

	cluster1 := &envoy_config_cluster_v3.Cluster{}
	err = proto.Unmarshal(res[0].Value, cluster1)
	require.NoError(t, err)

	cluster2 := &envoy_config_cluster_v3.Cluster{}
	err = proto.Unmarshal(res[1].Value, cluster2)
	require.NoError(t, err)

	cluster3 := &envoy_config_cluster_v3.Cluster{}
	err = proto.Unmarshal(res[2].Value, cluster3)
	require.NoError(t, err)

	clusterNames := []string{cluster1.Name, cluster2.Name, cluster3.Name}

	require.Contains(t, clusterNames, "dummy-namespace/dummy-backend")
	require.Contains(t, clusterNames, "dummy-namespace/another-dummy-backend")
	require.Contains(t, clusterNames, "dummy-namespace/default-backend")
}

func Test_getEnvoyConfigForIngress(t *testing.T) {
	cec, err := getEnvoyConfigForIngress(fakeClient(), baseIngress.DeepCopy(), false)
	require.NoError(t, err)

	assert.Equal(t, "cilium-ingress-dummy-namespace-dummy-ingress", cec.Name)
	assert.Equal(t, "dummy-namespace", cec.Namespace)

	// check services
	assert.Equal(t, []*v2alpha1.ServiceListener{
		{
			Name:      "cilium-ingress-dummy-ingress",
			Namespace: "dummy-namespace",
			Listener:  "cilium-ingress-dummy-namespace-dummy-ingress",
		},
	}, cec.Spec.Services)

	// check backendServices
	assert.Contains(t, cec.Spec.BackendServices, &v2alpha1.Service{
		Name:      "dummy-backend",
		Namespace: "dummy-namespace",
	})
	assert.Contains(t, cec.Spec.BackendServices, &v2alpha1.Service{
		Name:      "another-dummy-backend",
		Namespace: "dummy-namespace",
	})

	// check for count only, individual resource is covered in other tests
	// 1 listener, 1 route configuration, 3 clusters
	assert.Len(t, cec.Spec.Resources, 5)
}

func fakeClient() *fake.Clientset {
	client := fake.NewSimpleClientset()
	_, _ = client.CoreV1().Secrets("dummy-namespace").Create(context.TODO(), verySecureTLS, metav1.CreateOptions{})
	_, _ = client.CoreV1().Secrets("dummy-namespace").Create(context.TODO(), anotherVerySecureTLS, metav1.CreateOptions{})

	return client
}
