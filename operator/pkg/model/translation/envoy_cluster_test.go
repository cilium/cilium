// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/operator/pkg/model"
)

func Test_withClusterLbPolicy(t *testing.T) {
	fn := withClusterLbPolicy(int32(envoy_config_cluster_v3.Cluster_LEAST_REQUEST))

	t.Run("input is nil", func(t *testing.T) {
		cluster := fn(nil)
		require.Nil(t, cluster)
	})

	t.Run("input is not nil", func(t *testing.T) {
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)
		require.Equal(t, envoy_config_cluster_v3.Cluster_LEAST_REQUEST, cluster.LbPolicy)
	})
}

func Test_withOutlierDetection(t *testing.T) {
	t.Run("input is nil", func(t *testing.T) {
		fn := withOutlierDetection(true)
		cluster := fn(nil)
		require.Nil(t, cluster)
	})

	t.Run("input is not nil", func(t *testing.T) {
		t.Run("enabled", func(t *testing.T) {
			fn := withOutlierDetection(true)
			cluster := &envoy_config_cluster_v3.Cluster{}
			cluster = fn(cluster)
			require.NotNil(t, cluster.OutlierDetection)
			require.True(t, cluster.OutlierDetection.SplitExternalLocalOriginErrors)
		})

		t.Run("disabled", func(t *testing.T) {
			fn := withOutlierDetection(false)
			cluster := &envoy_config_cluster_v3.Cluster{}
			cluster = fn(cluster)
			require.NotNil(t, cluster.OutlierDetection)
			require.False(t, cluster.OutlierDetection.SplitExternalLocalOriginErrors)
		})
	})
}

func Test_withConnectionTimeout(t *testing.T) {
	fn := withConnectionTimeout(10)

	t.Run("input is nil", func(t *testing.T) {
		cluster := fn(nil)
		require.Nil(t, cluster)
	})

	t.Run("input is not nil", func(t *testing.T) {
		cluster := &envoy_config_cluster_v3.Cluster{}
		cluster = fn(cluster)
		require.Equal(t, int64(10), cluster.ConnectTimeout.Seconds)
	})
}

func Test_httpCluster(t *testing.T) {
	c := &cecTranslator{}
	res, err := c.httpCluster("dummy-name", "dummy-name", false, "", nil)
	require.NoError(t, err)

	cluster := &envoy_config_cluster_v3.Cluster{}
	err = proto.Unmarshal(res.Value, cluster)

	require.NoError(t, err)
	require.Equal(t, "dummy-name", cluster.Name)
	require.Equal(t, &envoy_config_cluster_v3.Cluster_Type{
		Type: envoy_config_cluster_v3.Cluster_EDS,
	}, cluster.ClusterDiscoveryType)
}

func Test_httpClusterWithTLSOriginationAllowsTLS13(t *testing.T) {
	c := &cecTranslator{}
	res, err := c.httpCluster("dummy-name", "dummy-name", false, "", &model.BackendTLSOrigination{
		SNI: "backend.example.com",
		CACertRef: &model.FullyQualifiedResource{
			Name:      "ca-cert",
			Namespace: "default",
		},
	})
	require.NoError(t, err)

	cluster := &envoy_config_cluster_v3.Cluster{}
	err = proto.Unmarshal(res.Value, cluster)
	require.NoError(t, err)
	require.Equal(t, "envoy.transport_sockets.tls", cluster.TransportSocket.Name)

	typedConfig := cluster.TransportSocket.ConfigType.(*envoy_config_core_v3.TransportSocket_TypedConfig)
	tlsContext := &envoy_config_tls.UpstreamTlsContext{}
	err = proto.Unmarshal(typedConfig.TypedConfig.Value, tlsContext)
	require.NoError(t, err)
	require.NotNil(t, tlsContext.CommonTlsContext.TlsParams)
	require.Equal(t, envoy_config_tls.TlsParameters_TLSv1_3, tlsContext.CommonTlsContext.TlsParams.TlsMaximumProtocolVersion)
}

func Test_tcpCluster(t *testing.T) {
	c := &cecTranslator{}
	res, err := c.httpCluster("dummy-name", "dummy-name", false, "", nil)
	require.NoError(t, err)

	cluster := &envoy_config_cluster_v3.Cluster{}
	err = proto.Unmarshal(res.Value, cluster)

	require.NoError(t, err)
	require.Equal(t, "dummy-name", cluster.Name)
	require.Equal(t, &envoy_config_cluster_v3.Cluster_Type{
		Type: envoy_config_cluster_v3.Cluster_EDS,
	}, cluster.ClusterDiscoveryType)
}

func extAuthBackend(ns, name string, port uint32, tls *model.BackendTLSOrigination) model.Backend {
	return model.Backend{
		Namespace: ns,
		Name:      name,
		Port:      &model.BackendPort{Port: port},
		TLS:       tls,
	}
}

func extAuthModel(protocol model.ExternalAuthProtocol, be model.Backend) *model.Model {
	return &model.Model{
		HTTP: []model.HTTPListener{
			{
				Routes: []model.HTTPRoute{
					{
						ExternalAuth: &model.HTTPExternalAuthFilter{
							Protocol: protocol,
							Backend:  be,
						},
					},
				},
			},
		},
	}
}

func Test_desiredEnvoyCluster_grpcExtAuthWithTLS(t *testing.T) {
	tls := &model.BackendTLSOrigination{
		SNI:       "authz.example.com",
		CACertRef: &model.FullyQualifiedResource{Name: "ca-cert", Namespace: "default"},
	}
	be := extAuthBackend("authns", "authsvc", 9001, tls)
	m := extAuthModel(model.ExternalAuthProtocolGRPC, be)

	c := &cecTranslator{}
	clusters, err := c.desiredEnvoyCluster(m)
	require.NoError(t, err)
	require.Len(t, clusters, 1)

	cluster := &envoy_config_cluster_v3.Cluster{}
	require.NoError(t, proto.Unmarshal(clusters[0].Value, cluster))

	require.Equal(t, "grpc:authns:authsvc:9001", cluster.Name)
	require.NotNil(t, cluster.TransportSocket, "expected TLS transport socket on gRPC ext_authz cluster")
	require.Equal(t, "envoy.transport_sockets.tls", cluster.TransportSocket.Name)

	typedConfig := cluster.TransportSocket.ConfigType.(*envoy_config_core_v3.TransportSocket_TypedConfig)
	tlsCtx := &envoy_config_tls.UpstreamTlsContext{}
	require.NoError(t, proto.Unmarshal(typedConfig.TypedConfig.Value, tlsCtx))
	require.Equal(t, "authz.example.com", tlsCtx.Sni)
}

func Test_desiredEnvoyCluster_httpExtAuthWithTLS(t *testing.T) {
	tls := &model.BackendTLSOrigination{
		SNI:       "authz.example.com",
		CACertRef: &model.FullyQualifiedResource{Name: "ca-cert", Namespace: "default"},
	}
	be := extAuthBackend("authns", "authsvc", 9001, tls)
	m := extAuthModel(model.ExternalAuthProtocolHTTP, be)

	c := &cecTranslator{}
	clusters, err := c.desiredEnvoyCluster(m)
	require.NoError(t, err)
	require.Len(t, clusters, 1)

	cluster := &envoy_config_cluster_v3.Cluster{}
	require.NoError(t, proto.Unmarshal(clusters[0].Value, cluster))

	require.Equal(t, "http:authns:authsvc:9001", cluster.Name)
	require.NotNil(t, cluster.TransportSocket, "expected TLS transport socket on HTTP ext_authz cluster")
	require.Equal(t, "envoy.transport_sockets.tls", cluster.TransportSocket.Name)

	typedConfig := cluster.TransportSocket.ConfigType.(*envoy_config_core_v3.TransportSocket_TypedConfig)
	tlsCtx := &envoy_config_tls.UpstreamTlsContext{}
	require.NoError(t, proto.Unmarshal(typedConfig.TypedConfig.Value, tlsCtx))
	require.Equal(t, "authz.example.com", tlsCtx.Sni)
}

func Test_getGRPCExtAuthBackends(t *testing.T) {
	grpcBe := extAuthBackend("ns", "grpc-svc", 8080, nil)
	httpBe := extAuthBackend("ns", "http-svc", 8081, nil)
	m := &model.Model{
		HTTP: []model.HTTPListener{
			{
				Routes: []model.HTTPRoute{
					{ExternalAuth: &model.HTTPExternalAuthFilter{Protocol: model.ExternalAuthProtocolGRPC, Backend: grpcBe}},
					{ExternalAuth: &model.HTTPExternalAuthFilter{Protocol: model.ExternalAuthProtocolHTTP, Backend: httpBe}},
					{ExternalAuth: &model.HTTPExternalAuthFilter{Protocol: model.ExternalAuthProtocolGRPC, Backend: grpcBe}},
				},
			},
		},
	}

	backends := getGRPCExtAuthBackends(m)
	require.Len(t, backends, 1)
	require.Equal(t, "grpc-svc", backends[0].Name)
}

func Test_getHTTPExtAuthBackends(t *testing.T) {
	grpcBe := extAuthBackend("ns", "grpc-svc", 8080, nil)
	httpBe := extAuthBackend("ns", "http-svc", 8081, nil)
	m := &model.Model{
		HTTP: []model.HTTPListener{
			{
				Routes: []model.HTTPRoute{
					{ExternalAuth: &model.HTTPExternalAuthFilter{Protocol: model.ExternalAuthProtocolGRPC, Backend: grpcBe}},
					{ExternalAuth: &model.HTTPExternalAuthFilter{Protocol: model.ExternalAuthProtocolHTTP, Backend: httpBe}},
					{ExternalAuth: &model.HTTPExternalAuthFilter{Protocol: model.ExternalAuthProtocolHTTP, Backend: httpBe}},
				},
			},
		},
	}

	backends := getHTTPExtAuthBackends(m)
	require.Len(t, backends, 1)
	require.Equal(t, "http-svc", backends[0].Name)
}
