// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/cilium/cilium/operator/pkg/model"
)

func Test_getHostNetworkListenerAddresses(t *testing.T) {
	testCases := []struct {
		desc                       string
		ports                      []uint32
		ipv4Enabled                bool
		ipv6Enabled                bool
		expectedPrimaryAdress      *envoy_config_core_v3.Address
		expectedAdditionalAdresses []*envoy_config_listener.AdditionalAddress
	}{
		{
			desc:                       "No ports - no address",
			ipv4Enabled:                true,
			ipv6Enabled:                true,
			expectedPrimaryAdress:      nil,
			expectedAdditionalAdresses: nil,
		},
		{
			desc:                       "No IP family - no address",
			ports:                      []uint32{55555},
			expectedPrimaryAdress:      nil,
			expectedAdditionalAdresses: nil,
		},
		{
			desc:        "IPv4 only",
			ports:       []uint32{55555},
			ipv4Enabled: true,
			ipv6Enabled: false,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 55555,
						},
					},
				},
			},
			expectedAdditionalAdresses: nil,
		},
		{
			desc:        "IPv6 only",
			ports:       []uint32{55555},
			ipv4Enabled: false,
			ipv6Enabled: true,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "::",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 55555,
						},
					},
				},
			},
			expectedAdditionalAdresses: nil,
		},
		{
			desc:        "IPv4 & IPv6",
			ports:       []uint32{55555},
			ipv4Enabled: true,
			ipv6Enabled: true,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 55555,
						},
					},
				},
			},
			expectedAdditionalAdresses: []*envoy_config_listener.AdditionalAddress{
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "::",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 55555,
								},
							},
						},
					},
				},
			},
		},
		{
			desc:        "IPv4 only with multiple ports",
			ports:       []uint32{44444, 55555},
			ipv4Enabled: true,
			ipv6Enabled: false,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 44444,
						},
					},
				},
			},
			expectedAdditionalAdresses: []*envoy_config_listener.AdditionalAddress{
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "0.0.0.0",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 55555,
								},
							},
						},
					},
				},
			},
		},
		{
			desc:        "IPv6 only with multiple ports",
			ports:       []uint32{44444, 55555},
			ipv4Enabled: false,
			ipv6Enabled: true,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "::",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 44444,
						},
					},
				},
			},
			expectedAdditionalAdresses: []*envoy_config_listener.AdditionalAddress{
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "::",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 55555,
								},
							},
						},
					},
				},
			},
		},
		{
			desc:        "IPv4 & IPv6 with multiple ports",
			ports:       []uint32{44444, 55555},
			ipv4Enabled: true,
			ipv6Enabled: true,
			expectedPrimaryAdress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "0.0.0.0",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 44444,
						},
					},
				},
			},
			expectedAdditionalAdresses: []*envoy_config_listener.AdditionalAddress{
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "::",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 44444,
								},
							},
						},
					},
				},
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "0.0.0.0",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 55555,
								},
							},
						},
					},
				},
				{
					Address: &envoy_config_core_v3.Address{
						Address: &envoy_config_core_v3.Address_SocketAddress{
							SocketAddress: &envoy_config_core_v3.SocketAddress{
								Protocol: envoy_config_core_v3.SocketAddress_TCP,
								Address:  "::",
								PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
									PortValue: 55555,
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			primaryAddress, additionalAddresses := getHostNetworkListenerAddresses(tC.ports, tC.ipv4Enabled, tC.ipv6Enabled)

			assert.Equal(t, tC.expectedPrimaryAdress, primaryAddress)
			assert.Equal(t, tC.expectedAdditionalAdresses, additionalAddresses)
		})
	}
}

func Test_withHostNetworkPortSorted(t *testing.T) {
	modifiedEnvoyListener1 := withHostNetworkPort(&model.Model{HTTP: []model.HTTPListener{{Port: 80}, {Port: 443}}}, true, true)(&envoy_config_listener.Listener{})
	modifiedEnvoyListener2 := withHostNetworkPort(&model.Model{HTTP: []model.HTTPListener{{Port: 443}, {Port: 80}}}, true, true)(&envoy_config_listener.Listener{})

	diffOutput := cmp.Diff(modifiedEnvoyListener1, modifiedEnvoyListener2, protocmp.Transform())
	if len(diffOutput) != 0 {
		t.Errorf("Modified Envoy Listeners did not match for different order of http listener ports:\n%s\n", diffOutput)
	}
}

func Test_toTransportSocket(t *testing.T) {
	tests := []struct {
		name                     string
		ciliumSecretNamespace    string
		tls                      []model.TLSSecret
		frontendValidation       *model.FrontendTLSValidation
		wantRequireClientCert    bool
		wantValidationContextSDS string
	}{
		{
			name:                  "server TLS only - no client validation",
			ciliumSecretNamespace: "cilium-secrets",
			tls: []model.TLSSecret{
				{Namespace: "default", Name: "server-cert"},
			},
			frontendValidation:       nil,
			wantRequireClientCert:    false,
			wantValidationContextSDS: "",
		},
		{
			name:                  "with frontend validation - AllowValidOnly mode",
			ciliumSecretNamespace: "cilium-secrets",
			tls: []model.TLSSecret{
				{Namespace: "default", Name: "server-cert"},
			},
			frontendValidation: &model.FrontendTLSValidation{
				CACertRefs: []model.FullyQualifiedResource{
					{Namespace: "default", Name: "client-ca"},
				},
				RequireClientCertificate: true,
			},
			wantRequireClientCert:    true,
			wantValidationContextSDS: "cilium-secrets/default-cfgmap-client-ca",
		},
		{
			name:                  "with frontend validation - AllowInsecureFallback mode",
			ciliumSecretNamespace: "cilium-secrets",
			tls: []model.TLSSecret{
				{Namespace: "default", Name: "server-cert"},
			},
			frontendValidation: &model.FrontendTLSValidation{
				CACertRefs: []model.FullyQualifiedResource{
					{Namespace: "gateway-ns", Name: "ca-bundle"},
				},
				RequireClientCertificate: false,
			},
			wantRequireClientCert:    false,
			wantValidationContextSDS: "cilium-secrets/gateway-ns-cfgmap-ca-bundle",
		},
		{
			name:                  "empty CACertRefs - no validation context",
			ciliumSecretNamespace: "cilium-secrets",
			tls: []model.TLSSecret{
				{Namespace: "default", Name: "server-cert"},
			},
			frontendValidation: &model.FrontendTLSValidation{
				CACertRefs:               []model.FullyQualifiedResource{},
				RequireClientCertificate: true,
			},
			wantRequireClientCert:    false,
			wantValidationContextSDS: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := toTransportSocket(tt.ciliumSecretNamespace, tt.tls, tt.frontendValidation)
			assert.NotNil(t, ts)
			assert.Equal(t, tlsTransportSocketType, ts.Name)

			// Unmarshal the DownstreamTlsContext
			typedConfig := ts.GetTypedConfig()
			assert.NotNil(t, typedConfig)

			var downstreamCtx envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext
			err := proto.Unmarshal(typedConfig.GetValue(), &downstreamCtx)
			assert.NoError(t, err)

			// Check RequireClientCertificate
			if tt.wantRequireClientCert {
				assert.NotNil(t, downstreamCtx.RequireClientCertificate)
				assert.True(t, downstreamCtx.RequireClientCertificate.GetValue())
			} else {
				// Either nil or false
				if downstreamCtx.RequireClientCertificate != nil {
					assert.False(t, downstreamCtx.RequireClientCertificate.GetValue())
				}
			}

			// Check ValidationContext SDS config
			if tt.wantValidationContextSDS != "" {
				sdsConfig := downstreamCtx.CommonTlsContext.GetValidationContextSdsSecretConfig()
				assert.NotNil(t, sdsConfig, "expected ValidationContextSdsSecretConfig to be set")
				assert.Equal(t, tt.wantValidationContextSDS, sdsConfig.Name)
			} else {
				assert.Nil(t, downstreamCtx.CommonTlsContext.GetValidationContextSdsSecretConfig())
			}

			// Verify server TLS certificates are present
			assert.NotEmpty(t, downstreamCtx.CommonTlsContext.TlsCertificateSdsSecretConfigs)
		})
	}
}

func Test_httpsFilterChains_SharedSecretDifferentValidation(t *testing.T) {
	translator := &cecTranslator{
		Config: Config{
			SecretsNamespace: "cilium-secrets",
		},
	}

	sharedSecret := model.TLSSecret{Name: "server-cert", Namespace: "gateway-ns"}
	m := &model.Model{
		HTTP: []model.HTTPListener{
			{
				Hostname: "a.example.com",
				TLS:      []model.TLSSecret{sharedSecret},
				FrontendTLSValidation: &model.FrontendTLSValidation{
					CACertRefs: []model.FullyQualifiedResource{
						{Namespace: "gateway-ns", Name: "client-ca-a"},
					},
					RequireClientCertificate: true,
				},
			},
			{
				Hostname: "b.example.com",
				TLS:      []model.TLSSecret{sharedSecret},
				FrontendTLSValidation: &model.FrontendTLSValidation{
					CACertRefs: []model.FullyQualifiedResource{
						{Namespace: "gateway-ns", Name: "client-ca-b"},
					},
					RequireClientCertificate: false,
				},
			},
		},
	}

	chains, err := translator.httpsFilterChains("listener", m)
	assert.NoError(t, err)
	assert.Len(t, chains, 2)

	gotByHostname := map[string]struct {
		requireClientCert bool
		validationSDS     string
	}{}

	for _, chain := range chains {
		assert.NotNil(t, chain.FilterChainMatch)
		assert.Len(t, chain.FilterChainMatch.ServerNames, 1)
		hostname := chain.FilterChainMatch.ServerNames[0]

		downstreamCtx := downstreamTLSContextFromTransportSocket(t, chain.TransportSocket)
		requireClientCert := downstreamCtx.RequireClientCertificate != nil && downstreamCtx.RequireClientCertificate.GetValue()
		validationSDS := ""
		if sds := downstreamCtx.CommonTlsContext.GetValidationContextSdsSecretConfig(); sds != nil {
			validationSDS = sds.Name
		}

		gotByHostname[hostname] = struct {
			requireClientCert bool
			validationSDS     string
		}{
			requireClientCert: requireClientCert,
			validationSDS:     validationSDS,
		}
	}

	assert.Equal(t, map[string]struct {
		requireClientCert bool
		validationSDS     string
	}{
		"a.example.com": {
			requireClientCert: true,
			validationSDS:     "cilium-secrets/gateway-ns-cfgmap-client-ca-a",
		},
		"b.example.com": {
			requireClientCert: false,
			validationSDS:     "cilium-secrets/gateway-ns-cfgmap-client-ca-b",
		},
	}, gotByHostname)
}

func Test_httpsFilterChains_DeterministicAcrossListenerOrder(t *testing.T) {
	translator := &cecTranslator{
		Config: Config{
			SecretsNamespace: "cilium-secrets",
		},
	}

	listeners := []model.HTTPListener{
		{
			Hostname: "b.example.com",
			TLS:      []model.TLSSecret{{Name: "shared-cert", Namespace: "gateway-ns"}},
			FrontendTLSValidation: &model.FrontendTLSValidation{
				CACertRefs: []model.FullyQualifiedResource{
					{Namespace: "gateway-ns", Name: "ca-fallback"},
				},
				RequireClientCertificate: false,
			},
		},
		{
			Hostname: "a.example.com",
			TLS:      []model.TLSSecret{{Name: "shared-cert", Namespace: "gateway-ns"}},
			FrontendTLSValidation: &model.FrontendTLSValidation{
				CACertRefs: []model.FullyQualifiedResource{
					{Namespace: "gateway-ns", Name: "ca-valid-only"},
				},
				RequireClientCertificate: true,
			},
		},
	}

	got1, err := translator.httpsFilterChains("listener", &model.Model{HTTP: listeners})
	assert.NoError(t, err)

	got2, err := translator.httpsFilterChains("listener", &model.Model{HTTP: []model.HTTPListener{listeners[1], listeners[0]}})
	assert.NoError(t, err)

	diffOutput := cmp.Diff(got1, got2, protocmp.Transform())
	assert.Emptyf(t, diffOutput, "HTTPS filter chains differ for reordered listeners:\n%s", diffOutput)
}

func downstreamTLSContextFromTransportSocket(t *testing.T, ts *envoy_config_core_v3.TransportSocket) *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext {
	t.Helper()

	assert.NotNil(t, ts)
	typedConfig := ts.GetTypedConfig()
	assert.NotNil(t, typedConfig)

	downstreamCtx := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{}
	err := proto.Unmarshal(typedConfig.GetValue(), downstreamCtx)
	assert.NoError(t, err)

	return downstreamCtx
}
