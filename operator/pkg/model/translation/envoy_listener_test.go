// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"sort"
	"testing"

	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/operator/pkg/model"
)

func TestNewHTTPListener(t *testing.T) {
	t.Run("without TLS", func(t *testing.T) {
		res, err := NewHTTPListener("dummy-name", "dummy-secret-namespace", nil)
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)

		require.Equal(t, "dummy-name", listener.Name)
		require.Len(t, listener.GetListenerFilters(), 1)
		require.Len(t, listener.GetFilterChains(), 1)
	})

	t.Run("TLS", func(t *testing.T) {
		res, err := NewHTTPListener("dummy-name", "dummy-secret-namespace", map[model.TLSSecret][]string{
			{Name: "dummy-secret-1", Namespace: "dummy-namespace"}: {"dummy.server.com"},
			{Name: "dummy-secret-2", Namespace: "dummy-namespace"}: {"dummy.anotherserver.com"},
		})
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
		var serverNames []string
		serverNames = append(serverNames, listener.GetFilterChains()[1].GetFilterChainMatch().ServerNames...)
		serverNames = append(serverNames, listener.GetFilterChains()[2].GetFilterChainMatch().ServerNames...)
		sort.Strings(serverNames)
		require.Equal(t, []string{"dummy.anotherserver.com", "dummy.server.com"}, serverNames)

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
}

func TestNewSNIListener(t *testing.T) {
	t.Run("normal SNI listener", func(t *testing.T) {
		res, err := NewSNIListener("dummy-name", map[string][]string{"dummy-namespace/dummy-service:443": {"example.org", "example.com"}})
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)

		require.Equal(t, "dummy-name", listener.Name)
		require.Len(t, listener.GetListenerFilters(), 1)
		require.Len(t, listener.GetFilterChains(), 1)
		require.Len(t, listener.GetFilterChains()[0].FilterChainMatch.ServerNames, 2)
	})
}
