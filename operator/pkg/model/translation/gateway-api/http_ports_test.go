// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"log/slog"
	"slices"
	"testing"
	"time"

	listenerpb "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routepb "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmpb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
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

func TestHTTPRoutePrecedenceAcrossListenerPorts(t *testing.T) {
	const hostname = "app.example.com"
	source := model.FullyQualifiedResource{Name: "gateway", Namespace: "default", Kind: "Gateway"}
	gw := gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: source.Name, Namespace: source.Namespace},
		Spec: gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{
			{Name: "public", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: ptr.To[gatewayv1.Hostname]("*.example.com")},
			{Name: "alternate", Port: 8080, Protocol: gatewayv1.HTTPProtocolType, Hostname: ptr.To[gatewayv1.Hostname](hostname)},
		}},
	}
	newRoute := func(name string, backend gatewayv1.ObjectName, timestamp int64) gatewayv1.HTTPRoute {
		return gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: source.Namespace, CreationTimestamp: metav1.NewTime(time.Unix(timestamp, 0))},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name)}}},
				Hostnames:       []gatewayv1.Hostname{hostname},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches: []gatewayv1.HTTPRouteMatch{{
						Path: &gatewayv1.HTTPPathMatch{Type: ptr.To(gatewayv1.PathMatchPathPrefix), Value: ptr.To("/")},
					}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{Name: backend, Port: ptr.To[gatewayv1.PortNumber](80)},
					}}},
				}},
			},
		}
	}
	input := ingestion.Input{Gateway: gw}
	for _, listener := range gw.Spec.Listeners {
		input.MergedListeners = append(input.MergedListeners, ingestion.ListenerWithContext{Listener: listener, Source: source})
	}
	for _, backend := range []string{"backend-a", "backend-b"} {
		input.Services = append(input.Services, corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: backend, Namespace: source.Namespace},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 80}}},
		})
	}
	older := newRoute("z-first", "backend-a", 1)
	newer := newRoute("a-second", "backend-b", 2)
	sameAge := newRoute("a-second", "backend-b", 1)
	cfg := translation.Config{HostNetworkConfig: translation.HostNetworkConfig{Enabled: true}}
	translator := NewTranslator(translation.NewCECTranslator(cfg), cfg)
	translate := func(t *testing.T, routes []gatewayv1.HTTPRoute) []*routepb.RouteConfiguration {
		t.Helper()
		input := input
		input.HTTPRoutes = routes
		m := ingestion.GatewayAPI(slog.Default(), input)
		cec, _, _, err := translator.Translate(m)
		require.NoError(t, err)
		var configs []*routepb.RouteConfiguration
		for _, res := range cec.Spec.Resources {
			if res.GetTypeUrl() != envoy.RouteTypeURL {
				continue
			}
			rc := &routepb.RouteConfiguration{}
			require.NoError(t, proto.Unmarshal(res.Value, rc))
			configs = append(configs, rc)
		}
		return configs
	}

	for _, tc := range []struct {
		name   string
		routes []gatewayv1.HTTPRoute
		want   []string
	}{
		{"oldest first", []gatewayv1.HTTPRoute{newer, older}, []string{"default:backend-a:80", "default:backend-b:80"}},
		{"name breaks timestamp tie", []gatewayv1.HTTPRoute{older, sameAge}, []string{"default:backend-b:80", "default:backend-a:80"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var routeConfigs []string
			for _, rc := range translate(t, tc.routes) {
				require.Len(t, rc.VirtualHosts, 1, rc.Name)
				routes := rc.VirtualHosts[0].Routes
				require.Len(t, routes, 2, rc.Name)
				for i, route := range routes {
					require.Equal(t, "/", route.GetMatch().GetPrefix())
					require.Equal(t, tc.want[i], route.GetRoute().GetCluster(), rc.Name)
				}
				routeConfigs = append(routeConfigs, rc.Name)
			}
			require.ElementsMatch(t, []string{"listener-80-insecure", "listener-8080-insecure"}, routeConfigs)
		})
	}

	for _, tc := range []struct {
		name           string
		olderHostnames []gatewayv1.Hostname
		newerHostnames []gatewayv1.Hostname
		olderPathType  gatewayv1.PathMatchType
	}{
		{
			name:           "exact hostname wins over older wildcard",
			olderHostnames: []gatewayv1.Hostname{"*.example.com"},
			newerHostnames: []gatewayv1.Hostname{hostname},
			olderPathType:  gatewayv1.PathMatchPathPrefix,
		},
		{
			name:           "matching hostname takes precedence over path",
			olderHostnames: []gatewayv1.Hostname{"*.example.com", "unrelated.example.com"},
			newerHostnames: []gatewayv1.Hostname{hostname, "*.example.com"},
			olderPathType:  gatewayv1.PathMatchExact,
		},
		{
			name:           "longer matching wildcard wins",
			olderHostnames: []gatewayv1.Hostname{"*.com"},
			newerHostnames: []gatewayv1.Hostname{"*.example.com"},
			olderPathType:  gatewayv1.PathMatchPathPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			olderRoute := older.DeepCopy()
			olderRoute.Spec.Hostnames = tc.olderHostnames
			olderRoute.Spec.Rules[0].Matches[0].Path.Type = ptr.To(tc.olderPathType)
			newerRoute := newer.DeepCopy()
			newerRoute.Spec.Hostnames = tc.newerHostnames
			for _, rc := range translate(t, []gatewayv1.HTTPRoute{*newerRoute, *olderRoute}) {
				if rc.Name != "listener-8080-insecure" {
					continue
				}
				require.Len(t, rc.VirtualHosts, 1)
				vhost := rc.VirtualHosts[0]
				require.Contains(t, vhost.Domains, hostname)
				require.NotEmpty(t, vhost.Routes)
				first := vhost.Routes[0]
				require.Equal(t, "/", first.GetMatch().GetPrefix())
				require.Nil(t, first.GetRoute().GetWeightedClusters(), "hostname precedence must select one backend")
				require.Equal(t, "default:backend-b:80", first.GetRoute().GetCluster())
				return
			}
			t.Fatal("missing route configuration for the exact-hostname listener")
		})
	}
}
