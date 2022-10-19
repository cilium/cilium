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

func TestNewListener(t *testing.T) {
	t.Run("without TLS", func(t *testing.T) {
		res, err := NewListener("dummy-name", "dummy-secret-namespace", nil)
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)

		require.Equal(t, "dummy-name", listener.Name)
		require.Len(t, listener.GetListenerFilters(), 1)
		require.Len(t, listener.GetFilterChains(), 1)
	})

	t.Run("TLS", func(t *testing.T) {
		res, err := NewListener("dummy-name", "dummy-secret-namespace", []model.TLSSecret{
			{
				Name:      "dummy-secret-1",
				Namespace: "dummy-namespace",
			},
			{
				Name:      "dummy-secret-2",
				Namespace: "dummy-namespace",
			},
		})
		require.Nil(t, err)

		listener := &envoy_config_listener.Listener{}
		err = proto.Unmarshal(res.Value, listener)
		require.Nil(t, err)

		require.Equal(t, "dummy-name", listener.Name)
		require.Len(t, listener.GetListenerFilters(), 1)
		require.Len(t, listener.GetFilterChains(), 2)
		require.Equal(t, "raw_buffer", listener.GetFilterChains()[0].GetFilterChainMatch().TransportProtocol)
		require.Equal(t, "tls", listener.GetFilterChains()[1].GetFilterChainMatch().TransportProtocol)
		require.Len(t, listener.GetFilterChains()[1].GetFilters(), 1)

		downStreamTLS := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{}
		err = proto.Unmarshal(listener.FilterChains[1].TransportSocket.ConfigType.(*envoy_config_core_v3.TransportSocket_TypedConfig).TypedConfig.Value, downStreamTLS)
		require.NoError(t, err)

		require.Len(t, downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs, 2)
		sort.Slice(downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs, func(i, j int) bool {
			return downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[i].Name < downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[j].Name
		})
		require.Equal(t, "dummy-secret-namespace/dummy-namespace-dummy-secret-1", downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[0].GetName())
		require.Equal(t, "dummy-secret-namespace/dummy-namespace-dummy-secret-2", downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[1].GetName())
	})
}
