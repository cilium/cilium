// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"slices"
	"sort"
	"testing"

	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	httpConnectionManagerv3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/cilium/cilium/operator/pkg/model"
)

func TestNewListener(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		res, err := newListener("dummy-name", "dummy-secret-namespace", false, nil, nil)
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)

		require.Equal(t, "dummy-name", listener.Name)
		require.Len(t, listener.GetListenerFilters(), 1)
		require.Empty(t, listener.GetFilterChains())
	})

	t.Run("without TLS", func(t *testing.T) {
		res, err := newListener("dummy-name", "dummy-secret-namespace", true, nil, nil)
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)

		require.Equal(t, "dummy-name", listener.Name)
		require.Len(t, listener.GetListenerFilters(), 1)
		require.Len(t, listener.GetFilterChains(), 1)
	})

	t.Run("with default XffNumTrustedHops", func(t *testing.T) {
		res, err := newListener("dummy-name", "dummy-secret-namespace", true, nil, nil)
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)
		require.Len(t, listener.GetFilterChains(), 1)
		require.Len(t, listener.GetFilterChains()[0].Filters, 1)
		httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
		err = proto.Unmarshal(listener.GetFilterChains()[0].Filters[0].ConfigType.(*envoy_config_listener.Filter_TypedConfig).TypedConfig.Value, httpConnectionManager)
		require.Nil(t, err)
		// Default value is 0
		require.Equal(t, uint32(0), httpConnectionManager.XffNumTrustedHops)

	})

	t.Run("without TLS with Proxy Protocol", func(t *testing.T) {
		res, err := newListener("dummy-name", "dummy-secret-namespace", true, nil, nil, WithProxyProtocol())
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)

		require.Equal(t, "dummy-name", listener.Name)

		listenerNames := []string{}
		for _, l := range listener.GetListenerFilters() {
			listenerNames = append(listenerNames, l.Name)
		}
		slices.Sort(listenerNames)
		require.Equal(t, []string{proxyProtocolType, tlsInspectorType}, listenerNames)
		require.Len(t, listener.GetFilterChains(), 1)
	})

	t.Run("stable filterchain sort-order with TLS", func(t *testing.T) {
		res1, err1 := newListener("dummy-name", "dummy-secret-namespace", true, map[model.TLSSecret][]string{
			{Name: "dummy-secret-1", Namespace: "dummy-namespace"}: {"dummy.server.com"},
			{Name: "dummy-secret-2", Namespace: "dummy-namespace"}: {"dummy.anotherserver.com"},
		}, nil)
		res2, err2 := newListener("dummy-name", "dummy-secret-namespace", true, map[model.TLSSecret][]string{
			{Name: "dummy-secret-2", Namespace: "dummy-namespace"}: {"dummy.anotherserver.com"},
			{Name: "dummy-secret-1", Namespace: "dummy-namespace"}: {"dummy.server.com"},
		}, nil)

		require.NoError(t, err1)
		require.NoError(t, err2)

		diffOutput := cmp.Diff(res1, res2, protocmp.Transform())
		if len(diffOutput) != 0 {
			t.Errorf("Listeners filterchain order did not match:\n%s\n", diffOutput)
		}
	})

	t.Run("with TLS (termination)", func(t *testing.T) {
		res, err := newListener("dummy-name", "dummy-secret-namespace", true, map[model.TLSSecret][]string{
			{Name: "dummy-secret-1", Namespace: "dummy-namespace"}: {"dummy.server.com"},
			{Name: "dummy-secret-2", Namespace: "dummy-namespace"}: {"dummy.anotherserver.com"},
		}, nil)
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)

		require.Equal(t, "dummy-name", listener.Name)
		require.Len(t, listener.GetListenerFilters(), 1)
		require.Len(t, listener.GetFilterChains(), 3)
		require.Equal(t, "raw_buffer", listener.GetFilterChains()[0].GetFilterChainMatch().TransportProtocol)
		require.Equal(t, "tls", listener.GetFilterChains()[1].GetFilterChainMatch().TransportProtocol)
		require.Equal(t, "tls", listener.GetFilterChains()[2].GetFilterChainMatch().TransportProtocol)
		require.Len(t, listener.GetFilterChains()[1].GetFilters(), 1)
		require.Equal(t, []string{"dummy.server.com"}, listener.GetFilterChains()[1].GetFilterChainMatch().ServerNames)
		require.Equal(t, []string{"dummy.anotherserver.com"}, listener.GetFilterChains()[2].GetFilterChainMatch().ServerNames)

		downStreamTLS := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{}
		err = proto.Unmarshal(listener.FilterChains[1].TransportSocket.ConfigType.(*envoy_config_core_v3.TransportSocket_TypedConfig).TypedConfig.Value, downStreamTLS)
		require.NoError(t, err)

		var secretNames []string
		require.Len(t, downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs, 1)
		sort.Slice(downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs, func(i, j int) bool {
			return downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[i].Name < downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[j].Name
		})
		secretNames = append(secretNames, downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[0].GetName())

		err = proto.Unmarshal(listener.FilterChains[2].TransportSocket.ConfigType.(*envoy_config_core_v3.TransportSocket_TypedConfig).TypedConfig.Value, downStreamTLS)
		require.NoError(t, err)

		require.Len(t, downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs, 1)
		sort.Slice(downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs, func(i, j int) bool {
			return downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[i].Name < downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[j].Name
		})
		secretNames = append(secretNames, downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[0].GetName())

		sort.Strings(secretNames)
		require.Equal(t, "dummy-secret-namespace/dummy-namespace-dummy-secret-1", secretNames[0])
		require.Equal(t, "dummy-secret-namespace/dummy-namespace-dummy-secret-2", secretNames[1])

	})

	t.Run("with TLS (passthrough)", func(t *testing.T) {
		res, err := newListener("dummy-name",
			"",
			false,
			nil,
			map[string][]string{
				"foo-namespace/dummy-service:443": {
					"foo.bar",
				},
				"dummy-namespace/dummy-service:443": {
					"example.org",
					"example.com",
				},
			},
		)
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)

		require.Equal(t, "dummy-name", listener.Name)
		require.Len(t, listener.GetListenerFilters(), 1)
		require.Len(t, listener.GetFilterChains(), 2)
		require.Equal(t, []string{"example.com", "example.org"}, listener.GetFilterChains()[0].FilterChainMatch.ServerNames)
		require.Equal(t, []string{"foo.bar"}, listener.GetFilterChains()[1].FilterChainMatch.ServerNames)
	})

	t.Run("stable filterchain sort-order for TLS passthrough", func(t *testing.T) {
		res1, err1 := newListener("dummy-name",
			"",
			false,
			nil,
			map[string][]string{
				"dummy-namespace/dummy-service:443": {
					"example.org",
					"example.com",
				},
				"foo-namespace/dummy-service:443": {
					"foo.bar",
				},
			},
		)
		res2, err2 := newListener("dummy-name",
			"",
			false,
			nil,
			map[string][]string{
				"foo-namespace/dummy-service:443": {
					"foo.bar",
				},
				"dummy-namespace/dummy-service:443": {
					"example.org",
					"example.com",
				},
			},
		)
		require.Nil(t, err1)
		require.Nil(t, err2)

		diffOutput := cmp.Diff(res1, res2, protocmp.Transform())
		if len(diffOutput) != 0 {
			t.Errorf("Listeners did not match:\n%s\n", diffOutput)
		}
	})

	t.Run("TLS passthrough with Proxy Protocol", func(t *testing.T) {
		res, err := newListener("dummy-name", "", false, nil, map[string][]string{"dummy-namespace/dummy-service:443": {"example.org", "example.com"}}, WithProxyProtocol())
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)

		require.Equal(t, "dummy-name", listener.Name)
		listenerNames := []string{}
		for _, l := range listener.GetListenerFilters() {
			listenerNames = append(listenerNames, l.Name)
		}
		slices.Sort(listenerNames)
		require.Equal(t, []string{proxyProtocolType, tlsInspectorType}, listenerNames)
		require.Len(t, listener.GetFilterChains(), 1)
		require.Len(t, listener.GetFilterChains()[0].FilterChainMatch.ServerNames, 2)
	})

	t.Run("Combined (non-TLS, TLS & TLS passthrough)", func(t *testing.T) {
		res, err := newListener("dummy-name",
			"dummy-namespace",
			true,
			map[model.TLSSecret][]string{
				{Name: "dummy-secret-1", Namespace: "dummy-namespace"}: {"dummy.server.com"},
				{Name: "dummy-secret-2", Namespace: "dummy-namespace"}: {"dummy.anotherserver.com"},
				{Name: "dummy-secret-3", Namespace: "dummy-namespace"}: {"foo.acme.com", "bar.acme.com"},
			},
			map[string][]string{
				"foo-namespace/dummy-service:443": {
					"foo.bar",
				},
				"dummy-namespace/dummy-service:443": {
					"example.org",
					"example.com",
				},
			},
		)
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)

		require.Equal(t, "dummy-name", listener.Name)
		require.Len(t, listener.GetListenerFilters(), 1)
		require.Len(t, listener.GetFilterChains(), 6)
		require.Equal(t, "raw_buffer", listener.GetFilterChains()[0].FilterChainMatch.TransportProtocol)
		require.Equal(t, "tls", listener.GetFilterChains()[1].FilterChainMatch.TransportProtocol)
		require.Equal(t, "tls", listener.GetFilterChains()[2].FilterChainMatch.TransportProtocol)
		require.Equal(t, "tls", listener.GetFilterChains()[3].FilterChainMatch.TransportProtocol)
		require.Equal(t, "tls", listener.GetFilterChains()[4].FilterChainMatch.TransportProtocol)
		require.Equal(t, "tls", listener.GetFilterChains()[5].FilterChainMatch.TransportProtocol)
		require.Empty(t, listener.GetFilterChains()[0].FilterChainMatch.ServerNames)
		require.Equal(t, []string{"dummy.server.com"}, listener.GetFilterChains()[1].FilterChainMatch.ServerNames)
		require.Equal(t, []string{"dummy.anotherserver.com"}, listener.GetFilterChains()[2].FilterChainMatch.ServerNames)
		require.Equal(t, []string{"bar.acme.com", "foo.acme.com"}, listener.GetFilterChains()[3].FilterChainMatch.ServerNames)
		require.Equal(t, []string{"example.com", "example.org"}, listener.GetFilterChains()[4].FilterChainMatch.ServerNames)
		require.Equal(t, []string{"foo.bar"}, listener.GetFilterChains()[5].FilterChainMatch.ServerNames)
	})
}
