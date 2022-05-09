// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package ingress

import (
	"syscall"
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

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func Test_getBackendServices(t *testing.T) {
	services := getBackendServices(baseIngress.DeepCopy())
	assert.Len(t, services, 3)
	assert.Equal(t, services, []*v2.Service{
		{
			Name:      "another-dummy-backend",
			Namespace: "dummy-namespace",
			Ports:     []string{"8081"},
		},
		{
			Name:      "default-backend",
			Namespace: "dummy-namespace",
			Ports:     []string{"8080"},
		},
		{
			Name:      "dummy-backend",
			Namespace: "dummy-namespace",
			Ports:     []string{"8080"},
		},
	})
}

func Test_getListenerResource(t *testing.T) {
	t.Run("with https enforcement", func(t *testing.T) {
		res, err := getListenerResource(baseIngress.DeepCopy(), "cilium-secrets", true)
		require.NoError(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.NoError(t, err)

		require.Len(t, listener.ListenerFilters, 1)
		require.Len(t, listener.FilterChains, 2)
		require.Len(t, listener.FilterChains[0].Filters, 1)
		require.Len(t, listener.SocketOptions, 4)
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

		require.Len(t, downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs, 1)
		require.Equal(t, "cilium-secrets/dummy-namespace-tls-very-secure-server-com", downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[0].GetName())
	})

	t.Run("without https enforcement", func(t *testing.T) {
		res, err := getListenerResource(baseIngress.DeepCopy(), "cilium-secrets", false)
		require.NoError(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.NoError(t, err)

		require.Len(t, listener.ListenerFilters, 1)
		require.Len(t, listener.FilterChains, 2)
		require.Len(t, listener.FilterChains[0].Filters, 1)
		require.Len(t, listener.SocketOptions, 4)
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

		require.Len(t, downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs, 1)
		require.Equal(t, "cilium-secrets/dummy-namespace-tls-very-secure-server-com", downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[0].GetName())
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
	require.Contains(t, clusters, "dummy-namespace/dummy-backend:8080")
	require.Contains(t, clusters, "dummy-namespace/another-dummy-backend:8081")
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

	require.Contains(t, clusterNames, "dummy-namespace/dummy-backend:8080")
	require.Contains(t, clusterNames, "dummy-namespace/another-dummy-backend:8081")
	require.Contains(t, clusterNames, "dummy-namespace/default-backend:8080")
}

func Test_getEnvoyConfigForIngress(t *testing.T) {
	cec, err := getEnvoyConfigForIngress(baseIngress.DeepCopy(), "cilium-secrets", false)
	require.NoError(t, err)

	assert.Equal(t, "cilium-ingress-dummy-namespace-dummy-ingress", cec.Name)
	assert.Equal(t, "dummy-namespace", cec.Namespace)

	// check services
	assert.Equal(t, []*v2.ServiceListener{
		{
			Name:      "cilium-ingress-dummy-ingress",
			Namespace: "dummy-namespace",
			Listener:  "cilium-ingress-dummy-namespace-dummy-ingress",
		},
	}, cec.Spec.Services)

	// check backendServices
	assert.Contains(t, cec.Spec.BackendServices, &v2.Service{
		Name:      "dummy-backend",
		Namespace: "dummy-namespace",
		Ports:     []string{"8080"},
	})
	assert.Contains(t, cec.Spec.BackendServices, &v2.Service{
		Name:      "another-dummy-backend",
		Namespace: "dummy-namespace",
		Ports:     []string{"8081"},
	})

	// check for count only, individual resource is covered in other tests
	// 1 listener, 1 route configuration, 3 clusters
	assert.Len(t, cec.Spec.Resources, 5)
}

func Test_getSocketOptions(t *testing.T) {
	type args struct {
		ingress *slim_networkingv1.Ingress
	}
	tests := []struct {
		name string
		args args
		want assert.ValueAssertionFunc
	}{
		{
			name: "sensible defaults",
			args: args{
				ingress: baseIngress,
			},
			want: assertSame([]*envoy_config_core_v3.SocketOption{
				{
					Description: "Enable TCP keep-alive, annotation io.cilium/tcp-keep-alive. (default to enabled)",
					Level:       syscall.SOL_SOCKET,
					Name:        syscall.SO_KEEPALIVE,
					Value:       &envoy_config_core_v3.SocketOption_IntValue{IntValue: 1},
					State:       envoy_config_core_v3.SocketOption_STATE_LISTENING,
				},
				{
					Description: "TCP keep-alive idle time (in seconds). Annotation io.cilium/tcp-keep-alive-idle (defaults to 10s)",
					Level:       syscall.IPPROTO_TCP,
					Name:        syscall.TCP_KEEPIDLE,
					Value:       &envoy_config_core_v3.SocketOption_IntValue{IntValue: 10},
					State:       envoy_config_core_v3.SocketOption_STATE_LISTENING,
				},
				{
					Description: "TCP keep-alive probe intervals (in seconds). Annotation io.cilium/tcp-keep-alive-probe-interval (defaults to 5s)",
					Level:       syscall.IPPROTO_TCP,
					Name:        syscall.TCP_KEEPINTVL,
					Value:       &envoy_config_core_v3.SocketOption_IntValue{IntValue: 5},
					State:       envoy_config_core_v3.SocketOption_STATE_LISTENING,
				},
				{
					Description: "TCP keep-alive probe max failures. Annotation io.cilium/tcp-keep-alive-probe-max-failures (defaults to 10)",
					Level:       syscall.IPPROTO_TCP,
					Name:        syscall.TCP_KEEPCNT,
					Value:       &envoy_config_core_v3.SocketOption_IntValue{IntValue: 10},
					State:       envoy_config_core_v3.SocketOption_STATE_LISTENING,
				},
			}),
		},
		{
			name: "disabled TCP keep-alive",
			args: args{
				ingress: &slim_networkingv1.Ingress{
					ObjectMeta: slim_metav1.ObjectMeta{
						Annotations: map[string]string{
							"io.cilium/tcp-keep-alive": "disabled",
						},
					},
				},
			},
			want: assertSame(nil),
		},
		{
			name: "user provided initial idle",
			args: args{
				ingress: &slim_networkingv1.Ingress{
					ObjectMeta: slim_metav1.ObjectMeta{
						Annotations: map[string]string{
							"io.cilium/tcp-keep-alive-idle": "20",
						},
					},
				},
			},
			want: assertContains(&envoy_config_core_v3.SocketOption{
				Description: "TCP keep-alive idle time (in seconds). Annotation io.cilium/tcp-keep-alive-idle (defaults to 10s)",
				Level:       syscall.IPPROTO_TCP,
				Name:        syscall.TCP_KEEPIDLE,
				Value:       &envoy_config_core_v3.SocketOption_IntValue{IntValue: 20},
				State:       envoy_config_core_v3.SocketOption_STATE_LISTENING,
			}),
		},
		{
			name: "user provided probe interval",
			args: args{
				ingress: &slim_networkingv1.Ingress{
					ObjectMeta: slim_metav1.ObjectMeta{
						Annotations: map[string]string{
							"io.cilium/tcp-keep-alive-probe-interval": "20",
						},
					},
				},
			},
			want: assertContains(&envoy_config_core_v3.SocketOption{
				Description: "TCP keep-alive probe intervals (in seconds). Annotation io.cilium/tcp-keep-alive-probe-interval (defaults to 5s)",
				Level:       syscall.IPPROTO_TCP,
				Name:        syscall.TCP_KEEPINTVL,
				Value:       &envoy_config_core_v3.SocketOption_IntValue{IntValue: 20},
				State:       envoy_config_core_v3.SocketOption_STATE_LISTENING,
			}),
		},
		{
			name: "user provided probe max failures",
			args: args{
				ingress: &slim_networkingv1.Ingress{
					ObjectMeta: slim_metav1.ObjectMeta{
						Annotations: map[string]string{
							"io.cilium/tcp-keep-alive-probe-max-failures": "10",
						},
					},
				},
			},
			want: assertContains(&envoy_config_core_v3.SocketOption{
				Description: "TCP keep-alive probe max failures. Annotation io.cilium/tcp-keep-alive-probe-max-failures (defaults to 10)",
				Level:       syscall.IPPROTO_TCP,
				Name:        syscall.TCP_KEEPCNT,
				Value:       &envoy_config_core_v3.SocketOption_IntValue{IntValue: 10},
				State:       envoy_config_core_v3.SocketOption_STATE_LISTENING,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socketOptions := getSocketOptions(tt.args.ingress)
			tt.want(t, socketOptions)
		})
	}
}

func assertSame(have []*envoy_config_core_v3.SocketOption) assert.ValueAssertionFunc {
	return func(t assert.TestingT, want interface{}, msg ...interface{}) bool {
		return assert.Equal(t, want, have, msg)
	}
}

func assertContains(expected *envoy_config_core_v3.SocketOption) assert.ValueAssertionFunc {
	return func(t assert.TestingT, have interface{}, msg ...interface{}) bool {
		return assert.Contains(t, have, expected, msg)
	}
}
