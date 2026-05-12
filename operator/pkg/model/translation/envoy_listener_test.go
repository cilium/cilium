// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_extensions_filters_network_tcp_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func Test_tlsPassthroughFilterChains_Backends(t *testing.T) {
	weight70 := int32(70)
	weight30 := int32(30)
	weight0 := int32(0)
	weight99 := int32(99)
	weightNegative := int32(-10)

	tests := []struct {
		name             string
		backends         []model.Backend
		wantFilterChains int
		wantStatPrefix   string
		wantCluster      string
		wantWeighted     []*envoy_extensions_filters_network_tcp_v3.TcpProxy_WeightedCluster_ClusterWeight
	}{
		{
			name:             "no valid backends emits no filter chain",
			wantFilterChains: 0,
		},
		{
			name: "single backend",
			backends: []model.Backend{
				tlsBackend("one", "backend-v1", 443, nil),
			},
			wantFilterChains: 1,
			wantStatPrefix:   "tls-passthrough:test.example.com",
			wantCluster:      "one:backend-v1:443",
		},
		{
			name: "weighted backends",
			backends: []model.Backend{
				tlsBackend("one", "backend-v1", 443, &weight70),
				tlsBackend("one", "backend-v2", 443, &weight30),
			},
			wantFilterChains: 1,
			wantStatPrefix:   "tls-passthrough:test.example.com",
			wantWeighted: []*envoy_extensions_filters_network_tcp_v3.TcpProxy_WeightedCluster_ClusterWeight{
				{Name: "one:backend-v1:443", Weight: 70},
				{Name: "one:backend-v2:443", Weight: 30},
			},
		},
		{
			name: "omitted weights default to one",
			backends: []model.Backend{
				tlsBackend("one", "backend-v1", 443, nil),
				tlsBackend("one", "backend-v2", 443, nil),
			},
			wantFilterChains: 1,
			wantStatPrefix:   "tls-passthrough:test.example.com",
			wantWeighted: []*envoy_extensions_filters_network_tcp_v3.TcpProxy_WeightedCluster_ClusterWeight{
				{Name: "one:backend-v1:443", Weight: 1},
				{Name: "one:backend-v2:443", Weight: 1},
			},
		},
		{
			name: "mixed omitted explicit zero and negative weights are deterministic",
			backends: []model.Backend{
				tlsBackend("one", "backend-v1", 443, nil),
				tlsBackend("one", "backend-v2", 443, &weight99),
				tlsBackend("one", "backend-v3", 443, &weight0),
				tlsBackend("one", "backend-v4", 443, &weightNegative),
			},
			wantFilterChains: 1,
			wantStatPrefix:   "tls-passthrough:test.example.com",
			wantWeighted: []*envoy_extensions_filters_network_tcp_v3.TcpProxy_WeightedCluster_ClusterWeight{
				{Name: "one:backend-v1:443", Weight: 1},
				{Name: "one:backend-v2:443", Weight: 99},
				{Name: "one:backend-v3:443", Weight: 0},
				{Name: "one:backend-v4:443", Weight: 0},
			},
		},
		{
			name: "all zero weights preserve configured zero values",
			backends: []model.Backend{
				tlsBackend("one", "backend-v1", 443, &weight0),
				tlsBackend("one", "backend-v2", 443, &weight0),
			},
			wantFilterChains: 1,
			wantStatPrefix:   "tls-passthrough:test.example.com",
			wantWeighted: []*envoy_extensions_filters_network_tcp_v3.TcpProxy_WeightedCluster_ClusterWeight{
				{Name: "one:backend-v1:443", Weight: 0},
				{Name: "one:backend-v2:443", Weight: 0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filterChains := tlsPassthroughFilterChains(&model.Model{
				TLSPassthrough: []model.TLSPassthroughListener{
					{
						Routes: []model.TLSPassthroughRoute{
							{
								Hostnames: []string{"test.example.com"},
								Backends:  tt.backends,
							},
						},
					},
				},
			})

			require.Len(t, filterChains, tt.wantFilterChains)
			if tt.wantFilterChains == 0 {
				return
			}

			tcpProxy := getTCPProxy(t, filterChains[0])
			assert.Equal(t, tt.wantStatPrefix, tcpProxy.GetStatPrefix())
			if tt.wantCluster != "" {
				assert.Equal(t, tt.wantCluster, tcpProxy.GetCluster())
				assert.Nil(t, tcpProxy.GetWeightedClusters())
				return
			}

			assert.Empty(t, tcpProxy.GetCluster())
			require.NotNil(t, tcpProxy.GetWeightedClusters())
			assert.Equal(t, tt.wantWeighted, tcpProxy.GetWeightedClusters().GetClusters())
		})
	}
}

func Test_tlsPassthroughFilterChains_DuplicateSNIRoutesPreserveCurrentBehavior(t *testing.T) {
	filterChains := tlsPassthroughFilterChains(&model.Model{
		TLSPassthrough: []model.TLSPassthroughListener{
			{
				Routes: []model.TLSPassthroughRoute{
					{
						Hostnames: []string{"test.example.com"},
						Backends: []model.Backend{
							tlsBackend("one", "backend-v1", 443, nil),
						},
					},
					{
						Hostnames: []string{"test.example.com"},
						Backends: []model.Backend{
							tlsBackend("one", "backend-v2", 443, nil),
						},
					},
				},
			},
		},
	})

	require.Len(t, filterChains, 2)
	assert.Equal(t, []string{"test.example.com"}, filterChains[0].GetFilterChainMatch().GetServerNames())
	assert.Equal(t, []string{"test.example.com"}, filterChains[1].GetFilterChainMatch().GetServerNames())
	assert.Equal(t, "tls-passthrough:test.example.com", getTCPProxy(t, filterChains[0]).GetStatPrefix())
	assert.Equal(t, "tls-passthrough:test.example.com", getTCPProxy(t, filterChains[1]).GetStatPrefix())
	assert.Equal(t, "one:backend-v1:443", getTCPProxy(t, filterChains[0]).GetCluster())
	assert.Equal(t, "one:backend-v2:443", getTCPProxy(t, filterChains[1]).GetCluster())
}

func Test_tlsPassthroughFilterChains_DeterministicOrder(t *testing.T) {
	weight70 := int32(70)
	weight30 := int32(30)

	modelA := &model.Model{
		TLSPassthrough: []model.TLSPassthroughListener{
			{
				Name: "listener-z",
				Port: 443,
				Routes: []model.TLSPassthroughRoute{
					{
						Hostnames: []string{"c.example.com"},
						Backends: []model.Backend{
							tlsBackend("two", "backend-z", 8443, nil),
						},
					},
				},
			},
			{
				Name: "listener-a",
				Port: 443,
				Routes: []model.TLSPassthroughRoute{
					{
						Hostnames: []string{"b.example.com"},
						Backends: []model.Backend{
							tlsBackend("one", "backend-b", 443, nil),
						},
					},
					{
						Hostnames: []string{"a.example.com"},
						Backends: []model.Backend{
							tlsBackend("one", "backend-a", 443, &weight70),
							tlsBackend("one", "backend-c", 443, &weight30),
						},
					},
				},
			},
		},
	}

	modelB := &model.Model{
		TLSPassthrough: []model.TLSPassthroughListener{
			{
				Name: "listener-a",
				Port: 443,
				Routes: []model.TLSPassthroughRoute{
					{
						Hostnames: []string{"a.example.com"},
						Backends: []model.Backend{
							tlsBackend("one", "backend-c", 443, &weight30),
							tlsBackend("one", "backend-a", 443, &weight70),
						},
					},
					{
						Hostnames: []string{"b.example.com"},
						Backends: []model.Backend{
							tlsBackend("one", "backend-b", 443, nil),
						},
					},
				},
			},
			{
				Name: "listener-z",
				Port: 443,
				Routes: []model.TLSPassthroughRoute{
					{
						Hostnames: []string{"c.example.com"},
						Backends: []model.Backend{
							tlsBackend("two", "backend-z", 8443, nil),
						},
					},
				},
			},
		},
	}

	filterChainsA := tlsPassthroughFilterChains(modelA)
	filterChainsB := tlsPassthroughFilterChains(modelB)

	diffOutput := cmp.Diff(filterChainsA, filterChainsB, protocmp.Transform())
	if len(diffOutput) != 0 {
		t.Fatalf("TLS passthrough filter chains were not deterministic across equivalent inputs:\n%s\n", diffOutput)
	}

	require.Len(t, filterChainsA, 3)
	assert.Equal(t, []string{"a.example.com"}, filterChainsA[0].GetFilterChainMatch().GetServerNames())
	assert.Equal(t, []string{"b.example.com"}, filterChainsA[1].GetFilterChainMatch().GetServerNames())
	assert.Equal(t, []string{"c.example.com"}, filterChainsA[2].GetFilterChainMatch().GetServerNames())

	tcpProxy := getTCPProxy(t, filterChainsA[0])
	assert.Equal(t, "tls-passthrough:a.example.com", tcpProxy.GetStatPrefix())
	require.NotNil(t, tcpProxy.GetWeightedClusters())
	assert.Equal(t, []*envoy_extensions_filters_network_tcp_v3.TcpProxy_WeightedCluster_ClusterWeight{
		{Name: "one:backend-a:443", Weight: 70},
		{Name: "one:backend-c:443", Weight: 30},
	}, tcpProxy.GetWeightedClusters().GetClusters())
}

func tlsBackend(namespace, name string, port uint32, weight *int32) model.Backend {
	return model.Backend{
		Namespace: namespace,
		Name:      name,
		Port: &model.BackendPort{
			Port: port,
		},
		Weight: weight,
	}
}

func getTCPProxy(t *testing.T, filterChain *envoy_config_listener.FilterChain) *envoy_extensions_filters_network_tcp_v3.TcpProxy {
	require.Len(t, filterChain.GetFilters(), 1)

	tcpProxy := &envoy_extensions_filters_network_tcp_v3.TcpProxy{}
	require.NoError(t, filterChain.GetFilters()[0].GetTypedConfig().UnmarshalTo(tcpProxy))
	return tcpProxy
}

func Test_withHostNetworkPortSorted(t *testing.T) {
	modifiedEnvoyListener1 := withHostNetworkPort(&model.Model{HTTP: []model.HTTPListener{{Port: 80}, {Port: 443}}}, true, true)(&envoy_config_listener.Listener{})
	modifiedEnvoyListener2 := withHostNetworkPort(&model.Model{HTTP: []model.HTTPListener{{Port: 443}, {Port: 80}}}, true, true)(&envoy_config_listener.Listener{})

	diffOutput := cmp.Diff(modifiedEnvoyListener1, modifiedEnvoyListener2, protocmp.Transform())
	if len(diffOutput) != 0 {
		t.Errorf("Modified Envoy Listeners did not match for different order of http listener ports:\n%s\n", diffOutput)
	}
}
