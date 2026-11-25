// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"log/slog"
	"slices"
	"testing"

	listenerpb "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routepb "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmpb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	"github.com/cilium/cilium/pkg/envoy"
)

func TestTLSRouteInvalidBackendKeepsListener(t *testing.T) {
	const hostname = "example.com"
	for _, tt := range []struct {
		name    string
		backend gatewayv1.BackendObjectReference
	}{
		{name: "nonexistent Service", backend: gatewayv1.BackendObjectReference{Name: "nonexistent"}},
		{
			name: "unknown backend kind",
			backend: gatewayv1.BackendObjectReference{
				Name:  "tls-backend",
				Group: new(gatewayv1.Group("unknownkind.example.com")),
				Kind:  new(gatewayv1.Kind("NonExistent")),
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gateway := gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default"},
			}
			listener := ingestion.ListenerWithContext{
				Listener: gatewayv1.Listener{
					Name: "tls", Port: 443, Protocol: gatewayv1.TLSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{Mode: new(gatewayv1.TLSModePassthrough)},
				},
				Source: model.FullyQualifiedResource{Name: gateway.Name, Namespace: gateway.Namespace, Kind: "Gateway"},
			}
			backend := tt.backend
			backend.Port = new(gatewayv1.PortNumber(443))
			route := gatewayv1.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: gateway.Namespace},
				Spec: gatewayv1.TLSRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gateway.Name)}}},
					Hostnames:       []gatewayv1.Hostname{hostname},
					Rules: []gatewayv1.TLSRouteRule{{
						BackendRefs: []gatewayv1.BackendRef{{BackendObjectReference: backend}},
					}},
				},
			}
			m := ingestion.GatewayAPI(slog.Default(), ingestion.Input{
				Gateway:         gateway,
				MergedListeners: []ingestion.ListenerWithContext{listener},
				TLSRoutes:       []gatewayv1.TLSRoute{route},
				Services: []corev1.Service{{
					ObjectMeta: metav1.ObjectMeta{Name: "tls-backend", Namespace: gateway.Namespace},
					Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 443}}},
				}},
			})

			cfg := translation.Config{}
			cfg.HostNetworkConfig.Enabled = true
			cfg.IPConfig.IPv4Enabled = true
			cec, _, _, err := NewTranslator(translation.NewCECTranslator(cfg), cfg).Translate(m)
			require.NoError(t, err)
			require.NotNil(t, cec)
			require.Empty(t, cec.Spec.BackendServices)
			require.Len(t, cec.Spec.Services, 1)
			require.Equal(t, []uint16{443}, cec.Spec.Services[0].Ports)
			require.Len(t, cec.Spec.Resources, 1)
			require.Equal(t, envoy.ListenerTypeURL, cec.Spec.Resources[0].GetTypeUrl())
			envoyListener := &listenerpb.Listener{}
			require.NoError(t, proto.Unmarshal(cec.Spec.Resources[0].Value, envoyListener))
			require.Equal(t, uint32(443), envoyListener.GetAddress().GetSocketAddress().GetPortValue())
			require.Len(t, envoyListener.FilterChains, 1)
			chain := envoyListener.FilterChains[0]
			require.Equal(t, "tls", chain.GetFilterChainMatch().GetTransportProtocol())
			require.Equal(t, []string{hostname}, chain.GetFilterChainMatch().GetServerNames())
			require.Empty(t, chain.Filters)
		})
	}
}

func TestHTTPListenerPortIsolation(t *testing.T) {
	for _, protocols := range []struct {
		name               string
		https, passthrough bool
	}{
		{name: "http"},
		{name: "http-and-https", https: true},
		{name: "http-and-passthrough", passthrough: true},
		{name: "http-https-and-passthrough", https: true, passthrough: true},
	} {
		for _, hostNetwork := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/host-network=%t", protocols.name, hostNetwork), func(t *testing.T) {
				m := &model.Model{}
				cfg := translation.Config{}
				readInput(t, "testdata/basic_http_multi_port_listener/input.yaml", m)
				readInput(t, "testdata/basic_http_multi_port_listener/config-input.yaml", &cfg)
				cfg.HostNetworkConfig.Enabled = hostNetwork
				if protocols.https {
					secure := m.HTTP[0]
					secure.Name = "https"
					secure.Hostname = "secure.example.test"
					secure.TLS = []model.TLSSecret{{Name: "cert", Namespace: "default"}}
					m.HTTP = append(m.HTTP, secure)
				}
				if protocols.passthrough {
					m.TLSPassthrough = []model.TLSPassthroughListener{
						{
							Port:     8080,
							Hostname: "pass.example.test",
							Sources:  m.HTTP[0].Sources,
							Routes: []model.TLSPassthroughRoute{
								{
									Hostnames: []string{"pass.example.test"},
									Backends:  []model.Backend{{Name: "tls", Namespace: "default", Port: &model.BackendPort{Port: 8443}}},
								},
							},
						},
					}
				}
				// Input ordering must not determine which listener's backend or redirect
				// port wins when two listeners use the same hostname and path.
				for _, reverse := range []bool{false, true} {
					if reverse {
						slices.Reverse(m.HTTP)
					}
					cec, _, _, err := NewTranslator(translation.NewCECTranslator(cfg), cfg).Translate(m)
					require.NoError(t, err)
					listeners := map[string]*listenerpb.Listener{}
					routes := map[string]*routepb.RouteConfiguration{}
					for _, resource := range cec.Spec.Resources {
						switch resource.GetTypeUrl() {
						case envoy.ListenerTypeURL:
							l := &listenerpb.Listener{}
							require.NoError(t, proto.Unmarshal(resource.Value, l))
							listeners[l.Name] = l
						case envoy.RouteTypeURL:
							r := &routepb.RouteConfiguration{}
							require.NoError(t, proto.Unmarshal(resource.Value, r))
							routes[r.Name] = r
						}
					}
					byPort := map[uint16]*listenerpb.Listener{}
					for _, service := range cec.Spec.Services {
						for _, port := range service.Ports {
							require.NotContains(t, byPort, port, "one Envoy listener per port")
							name := service.Listener
							if name == "" {
								name = "listener"
							}
							require.Contains(t, listeners, name)
							byPort[port] = listeners[name]
						}
					}
					require.Len(t, byPort, 3)
					for _, port := range []uint16{8080, 8081, 8082} {
						require.Contains(t, byPort, port)
						l := byPort[port]
						var httpRoutes *routepb.RouteConfiguration
						hasHTTPS, hasPassthrough := false, false
						for _, fc := range l.FilterChains {
							if fc.GetTransportSocket().GetName() == "envoy.transport_sockets.tls" {
								hasHTTPS = true
							}
							for _, filter := range fc.Filters {
								if filter.Name == "envoy.filters.network.tcp_proxy" {
									hasPassthrough = true
								}
							}
							if fc.GetFilterChainMatch().GetTransportProtocol() != "raw_buffer" {
								continue
							}
							hcm := &hcmpb.HttpConnectionManager{}
							require.NoError(t, proto.Unmarshal(fc.Filters[0].GetTypedConfig().Value, hcm))
							require.Contains(t, routes, hcm.GetRds().GetRouteConfigName())
							httpRoutes = routes[hcm.GetRds().GetRouteConfigName()]
						}
						if port == 8080 {
							require.Equal(t, protocols.https, hasHTTPS)
							require.Equal(t, protocols.passthrough, hasPassthrough)
						}
						require.NotNil(t, httpRoutes, "plaintext HTTP must survive TLS on the same port")
						if port == 8082 {
							require.Empty(t, httpRoutes.VirtualHosts)
							continue
						}
						require.Len(t, httpRoutes.VirtualHosts, 1)
						var root *routepb.Route
						for _, r := range httpRoutes.VirtualHosts[0].Routes {
							if r.GetMatch().GetPrefix() == "/" {
								root = r
							}
							if r.GetRedirect() != nil {
								require.Equal(t, uint32(port), r.GetRedirect().PortRedirect)
							}
						}
						require.NotNil(t, root)
						expected := "default:base:8080"
						if port == 8081 {
							expected = "apps:extra:9090"
						}
						require.Equal(t, expected, root.GetRoute().GetCluster())
						require.Nil(t, root.GetRoute().GetWeightedClusters(), "backends from different listeners must not merge")
						if hostNetwork {
							require.Equal(t, uint32(port), l.GetAddress().GetSocketAddress().GetPortValue())
							require.Empty(t, l.AdditionalAddresses)
						}
					}
				}
			})
		}
	}
}
