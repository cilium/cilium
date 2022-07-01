// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package ingress

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"syscall"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_extensions_filters_network_http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	envoy_config_upstream "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	envoy_type_matcher_v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/operator/pkg/ingress/annotations"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
)

const (
	wildCard       = "*"
	envoyAuthority = ":authority"
)

type envoyConfigManager struct {
	informer   cache.Controller
	store      cache.Store
	maxRetries int
}

func newEnvoyConfigManager(maxRetries int) (*envoyConfigManager, error) {
	manager := &envoyConfigManager{
		maxRetries: maxRetries,
	}

	// setup store and informer only for endpoints having label cilium.io/ingress
	manager.store, manager.informer = informer.NewInformer(
		cache.NewListWatchFromClient(k8s.CiliumClient().CiliumV2().RESTClient(), v2.CECPluralName, corev1.NamespaceAll, fields.Everything()),
		&v2.CiliumEnvoyConfig{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
	)

	go manager.informer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, manager.informer.HasSynced) {
		return manager, fmt.Errorf("unable to sync envoy configs")
	}
	return manager, nil
}

// getByKey is a wrapper of Store.GetByKey but with concrete Endpoint object
func (em *envoyConfigManager) getByKey(key string) (*v2.CiliumEnvoyConfig, bool, error) {
	objFromCache, exists, err := em.store.GetByKey(key)
	if objFromCache == nil || !exists || err != nil {
		return nil, exists, err
	}
	envoyConfig, ok := objFromCache.(*v2.CiliumEnvoyConfig)
	if !ok {
		return nil, exists, fmt.Errorf("got invalid object from cache")
	}
	return envoyConfig, exists, err
}

func getCECNameForIngress(ingress *slim_networkingv1.Ingress) string {
	return ciliumIngressPrefix + ingress.Namespace + "-" + ingress.Name
}

func getTransportSockets(ingress *slim_networkingv1.Ingress, secretNamespace string) (map[string]*envoy_config_core_v3.TransportSocket, error) {
	tls := make(map[string]*envoy_config_core_v3.TransportSocket)
	for _, tlsConfig := range ingress.Spec.TLS {
		for _, host := range tlsConfig.Hosts {
			sdsName := getSyncedSecretKey(secretNamespace, ingress.GetNamespace(), tlsConfig.SecretName)
			downStreamContext := envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
				CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
					TlsCertificateSdsSecretConfigs: []*envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig{
						{
							Name: sdsName,
							SdsConfig: &envoy_config_core_v3.ConfigSource{
								ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_ApiConfigSource{
									ApiConfigSource: &envoy_config_core_v3.ApiConfigSource{
										ApiType:             envoy_config_core_v3.ApiConfigSource_GRPC,
										TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
										GrpcServices: []*envoy_config_core_v3.GrpcService{
											{
												TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
													EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
														ClusterName: envoy.CiliumXDSClusterName,
													},
												},
											},
										},
									},
								},
								ResourceApiVersion: envoy_config_core_v3.ApiVersion_V3,
							},
						},
					},
					ValidationContextType: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContextSdsSecretConfig{
						ValidationContextSdsSecretConfig: &envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig{
							Name: sdsName,
							SdsConfig: &envoy_config_core_v3.ConfigSource{
								ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_ApiConfigSource{
									ApiConfigSource: &envoy_config_core_v3.ApiConfigSource{
										ApiType:             envoy_config_core_v3.ApiConfigSource_GRPC,
										TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
										GrpcServices: []*envoy_config_core_v3.GrpcService{
											{
												TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
													EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
														ClusterName: envoy.CiliumXDSClusterName,
													},
												},
											},
										},
									},
								},
								ResourceApiVersion: envoy_config_core_v3.ApiVersion_V3,
							},
						},
					},
				},
			}
			upstreamContextBytes, err := proto.Marshal(&downStreamContext)
			if err != nil {
				return nil, err
			}
			tls[host] = &envoy_config_core_v3.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
					TypedConfig: &anypb.Any{
						TypeUrl: envoy.DownstreamTlsContextURL,
						Value:   upstreamContextBytes,
					},
				},
			}
		}
	}
	return tls, nil
}

func getEnvoyConfigForIngress(ingress *slim_networkingv1.Ingress, secretsNamespace string, enforcedHTTPS bool) (*v2.CiliumEnvoyConfig, error) {
	backendServices := getBackendServices(ingress)
	resources, err := getResources(ingress, backendServices, secretsNamespace, enforcedHTTPS)
	if err != nil {
		return nil, err
	}
	return &v2.CiliumEnvoyConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       v2.CECKindDefinition,
			APIVersion: v2.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      getCECNameForIngress(ingress),
			Namespace: ingress.GetNamespace(),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: slim_networkingv1.SchemeGroupVersion.String(),
					Kind:       "Ingress",
					Name:       ingress.Name,
					UID:        ingress.UID,
				},
			},
		},
		Spec: v2.CiliumEnvoyConfigSpec{
			Services: []*v2.ServiceListener{
				{
					Name:      getServiceNameForIngress(ingress),
					Namespace: ingress.Namespace,
					Listener:  getCECNameForIngress(ingress),
				},
			},
			BackendServices: backendServices,
			Resources:       resources,
		},
	}, nil
}

func getBackendServices(ingress *slim_networkingv1.Ingress) []*v2.Service {
	var sortedServiceNames []string
	// make sure that we will not have any duplicated service
	serviceMap := map[string][]string{}

	if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
		name := ingress.Spec.DefaultBackend.Service.Name
		serviceMap[name] = append(serviceMap[name], getServiceFrontEndPort(ingress.Spec.DefaultBackend.Service))
	}

	for _, rule := range ingress.Spec.Rules {
		for _, path := range rule.HTTP.Paths {
			name := path.Backend.Service.Name
			serviceMap[name] = append(serviceMap[name], getServiceFrontEndPort(path.Backend.Service))
		}
	}

	for k := range serviceMap {
		sortedServiceNames = append(sortedServiceNames, k)
	}
	sort.Strings(sortedServiceNames)

	var backendServices []*v2.Service
	for _, name := range sortedServiceNames {
		backendServices = append(backendServices, &v2.Service{
			Namespace: ingress.Namespace,
			Name:      name,
			Ports:     sortAndUnique(serviceMap[name]),
		})
	}
	return backendServices
}

func getResources(ingress *slim_networkingv1.Ingress, backendServices []*v2.Service, secretsNamespace string, enforcedHTTPS bool) ([]v2.XDSResource, error) {
	var resources []v2.XDSResource
	listener, err := getListenerResource(ingress, secretsNamespace, enforcedHTTPS)
	if err != nil {
		return nil, err
	}
	resources = append(resources, listener)

	routeConfig, err := getRouteConfigurationResource(ingress)
	if err != nil {
		return nil, err
	}
	resources = append(resources, routeConfig)

	if enforcedHTTPS && tlsEnabled(ingress) {
		redirectRoute, err := getRedirectRouteConfigurationResource(ingress)
		if err != nil {
			return nil, err
		}
		resources = append(resources, redirectRoute)
	}

	clusters, err := getClusterResources(backendServices)
	if err != nil {
		return nil, err
	}
	resources = append(resources, clusters...)
	return resources, nil
}

func getListenerResource(ingress *slim_networkingv1.Ingress, secretNamespace string, enforcedHTTPS bool) (v2.XDSResource, error) {
	cecName := getCECNameForIngress(ingress)
	defaultHttpConnectionManager, err := getConnectionManager(cecName, fmt.Sprintf("%s_route", cecName))
	if err != nil {
		return v2.XDSResource{}, nil
	}

	var filterChains []*envoy_config_listener.FilterChain
	if !tlsEnabled(ingress) {
		filterChains = []*envoy_config_listener.FilterChain{
			{
				FilterChainMatch: &envoy_config_listener.FilterChainMatch{
					TransportProtocol: "raw_buffer",
				},
				Filters: []*envoy_config_listener.Filter{
					{
						Name: "envoy.filters.network.http_connection_manager",
						ConfigType: &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: defaultHttpConnectionManager.Any,
						},
					},
				},
			},
		}
	} else {
		insecureHttpConnectionManager := defaultHttpConnectionManager
		if enforcedHTTPS {
			insecureHttpConnectionManager, err = getConnectionManager(cecName, fmt.Sprintf("%s_redirect", cecName))
			if err != nil {
				return v2.XDSResource{}, nil
			}
		}

		transportSockets, err := getTransportSockets(ingress, secretNamespace)
		if err != nil {
			log.WithError(err).Error("Failed for construct transport sockets")
			return v2.XDSResource{}, err
		}

		// TODO(tam) extend to list of tls
		// just take the first one for now
		var tlsConf *envoy_config_core_v3.TransportSocket
		if len(ingress.Spec.TLS[0].Hosts) > 0 {
			domain := ingress.Spec.TLS[0].Hosts[0]
			tlsConf = transportSockets[domain]
		}

		filterChains = []*envoy_config_listener.FilterChain{
			{
				FilterChainMatch: &envoy_config_listener.FilterChainMatch{
					TransportProtocol: "raw_buffer",
				},
				Filters: []*envoy_config_listener.Filter{
					{
						Name: "envoy.filters.network.http_connection_manager",
						ConfigType: &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: insecureHttpConnectionManager.Any,
						},
					},
				},
			},
			{
				FilterChainMatch: &envoy_config_listener.FilterChainMatch{
					TransportProtocol: "tls",
				},
				Filters: []*envoy_config_listener.Filter{
					{
						Name: "envoy.filters.network.http_connection_manager",
						ConfigType: &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: defaultHttpConnectionManager.Any,
						},
					},
				},
				TransportSocket: tlsConf,
			},
		}
	}

	listener := envoy_config_listener.Listener{
		Name:         getCECNameForIngress(ingress),
		FilterChains: filterChains,
		ListenerFilters: []*envoy_config_listener.ListenerFilter{
			{
				Name: "envoy.filters.listener.tls_inspector",
			},
		},
		SocketOptions: getSocketOptions(ingress),
	}

	listenerBytes, err := proto.Marshal(&listener)
	if err != nil {
		return v2.XDSResource{}, err
	}
	return v2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.ListenerTypeURL,
			Value:   listenerBytes,
		},
	}, nil
}

func getConnectionManager(name string, routeName string) (v2.XDSResource, error) {
	var connectionManager envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager
	connectionManager = envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager{
		StatPrefix: name,
		RouteSpecifier: &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager_Rds{
			Rds: &envoy_extensions_filters_network_http_connection_manager_v3.Rds{
				RouteConfigName: routeName,
			},
		},
		HttpFilters: []*envoy_extensions_filters_network_http_connection_manager_v3.HttpFilter{
			{Name: "envoy.filters.http.router"},
		},
	}

	connectionManagerBytes, err := proto.Marshal(&connectionManager)
	if err != nil {
		return v2.XDSResource{}, err
	}

	return v2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.HttpConnectionManagerTypeURL,
			Value:   connectionManagerBytes,
		},
	}, nil
}

func getClusterResources(backendServices []*v2.Service) ([]v2.XDSResource, error) {
	var resources []v2.XDSResource
	for _, service := range backendServices {
		for _, port := range service.Ports {
			cluster := envoy_config_cluster_v3.Cluster{
				Name:           fmt.Sprintf("%s/%s:%s", service.Namespace, service.Name, port),
				ConnectTimeout: &durationpb.Duration{Seconds: 5},
				LbPolicy:       envoy_config_cluster_v3.Cluster_ROUND_ROBIN,
				TypedExtensionProtocolOptions: map[string]*anypb.Any{
					"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": toAny(&envoy_config_upstream.HttpProtocolOptions{
						UpstreamProtocolOptions: &envoy_config_upstream.HttpProtocolOptions_UseDownstreamProtocolConfig{
							UseDownstreamProtocolConfig: &envoy_config_upstream.HttpProtocolOptions_UseDownstreamHttpConfig{
								// Empty HTTP/2 options has no effect, so this should not be needed
								Http2ProtocolOptions: &envoy_config_core_v3.Http2ProtocolOptions{},
							},
						},
					}),
				},
				OutlierDetection: &envoy_config_cluster_v3.OutlierDetection{
					SplitExternalLocalOriginErrors: true,
					// The number of consecutive locally originated failures before ejection occurs.
					ConsecutiveLocalOriginFailure: &wrapperspb.UInt32Value{Value: 2},
				},
				ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
					Type: envoy_config_cluster_v3.Cluster_EDS,
				},
			}
			clusterBytes, err := proto.Marshal(&cluster)
			if err != nil {
				return nil, err
			}
			resources = append(resources, v2.XDSResource{
				Any: &anypb.Any{
					TypeUrl: envoy.ClusterTypeURL,
					Value:   clusterBytes,
				},
			})
		}
	}
	return resources, nil
}

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		log.WithError(err).Errorf("invalid message %s", message)
		return nil
	}
	return a
}

func getRouteMatch(host string, ingressPath slim_networkingv1.HTTPIngressPath) *envoy_config_route_v3.RouteMatch {
	headerMatchers := getHeaderMatchers(host)
	if ingressPath.PathType == nil || *ingressPath.PathType == slim_networkingv1.PathTypeImplementationSpecific ||
		*ingressPath.PathType == slim_networkingv1.PathTypePrefix {
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
				SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
					EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{},
					Regex:      getMatchingPrefixRegex(ingressPath.Path),
				},
			},
			Headers: headerMatchers,
		}
	}
	if *ingressPath.PathType == slim_networkingv1.PathTypeExact {
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
				Path: ingressPath.Path,
			},
			Headers: headerMatchers,
		}
	}
	return nil
}

func getHeaderMatchers(host string) []*envoy_config_route_v3.HeaderMatcher {
	if len(host) == 0 || host == wildCard || !strings.Contains(host, wildCard) {
		return nil
	}
	// Make sure that wildcard character only match one single dns domain.
	// For example, if host is *.foo.com, baz.bar.foo.com should not match
	return []*envoy_config_route_v3.HeaderMatcher{
		{
			Name: envoyAuthority,
			HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
				StringMatch: &envoy_type_matcher_v3.StringMatcher{
					MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
						SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
							EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{},
							Regex:      getMatchingHeaderRegex(host),
						},
					},
				},
			},
		},
	}
}

func getVirtualHost(ingress *slim_networkingv1.Ingress, rule slim_networkingv1.IngressRule) *envoy_config_route_v3.VirtualHost {
	routes := make(SortableRoute, 0, len(rule.HTTP.Paths))
	for _, path := range rule.HTTP.Paths {
		route := envoy_config_route_v3.Route{
			Match: getRouteMatch(rule.Host, path),
			Action: &envoy_config_route_v3.Route_Route{
				Route: &envoy_config_route_v3.RouteAction{
					ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
						Cluster: getClusterNameWithPort(ingress.Namespace, path.Backend.Service),
					},
					MaxStreamDuration: &envoy_config_route_v3.RouteAction_MaxStreamDuration{
						MaxStreamDuration: &durationpb.Duration{
							Seconds: 0,
						},
					},
				},
			},
		}

		routes = append(routes, &route)
	}

	// This is to make sure that the Exact match is always having higher priority.
	// Each route entry in the virtual host is checked, in order. If there is a match, the route is used and no further route checks are made.
	// Related docs https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/route_matching
	sort.Sort(routes)

	domains := []string{wildCard}
	if rule.Host != "" {
		domains = []string{
			rule.Host,
			// match authority header with port (e.g. "example.com:80")
			net.JoinHostPort(rule.Host, wildCard),
		}
	}
	return &envoy_config_route_v3.VirtualHost{
		Name:    domains[0],
		Domains: domains,
		Routes:  routes,
	}
}

func getRouteConfigurationResource(ingress *slim_networkingv1.Ingress) (v2.XDSResource, error) {
	var virtualhosts []*envoy_config_route_v3.VirtualHost
	for _, rule := range ingress.Spec.Rules {
		virtualhosts = append(virtualhosts, getVirtualHost(ingress, rule))
	}

	// The default backend route should be the last one
	if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
		route := &envoy_config_route_v3.Route{
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
					Prefix: "/",
				},
			},
			Action: &envoy_config_route_v3.Route_Route{
				Route: &envoy_config_route_v3.RouteAction{
					ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
						Cluster: getClusterNameWithPort(ingress.Namespace, ingress.Spec.DefaultBackend.Service),
					},
				},
			},
		}
		virtualhosts = append(virtualhosts, &envoy_config_route_v3.VirtualHost{
			Name:    "default-backend",
			Domains: []string{wildCard},
			Routes:  []*envoy_config_route_v3.Route{route},
		})
	}

	routeConfig := envoy_config_route_v3.RouteConfiguration{
		Name:         getCECNameForIngress(ingress) + "_route",
		VirtualHosts: virtualhosts,
	}
	routeBytes, err := proto.Marshal(&routeConfig)
	if err != nil {
		return v2.XDSResource{}, err
	}
	return v2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.RouteTypeURL,
			Value:   routeBytes,
		},
	}, nil
}

func getRedirectRouteConfigurationResource(ingress *slim_networkingv1.Ingress) (v2.XDSResource, error) {
	route := &envoy_config_route_v3.Route{
		Match: &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
				Prefix: "/",
			},
		},
		Action: &envoy_config_route_v3.Route_Redirect{
			Redirect: &envoy_config_route_v3.RedirectAction{
				SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_HttpsRedirect{
					HttpsRedirect: true,
				},
				ResponseCode: envoy_config_route_v3.RedirectAction_PERMANENT_REDIRECT,
			},
		},
	}

	virtualHost := &envoy_config_route_v3.VirtualHost{
		Name:    "default-redirect",
		Domains: []string{wildCard},
		Routes:  []*envoy_config_route_v3.Route{route},
	}

	routeConfig := envoy_config_route_v3.RouteConfiguration{
		Name:         getCECNameForIngress(ingress) + "_redirect",
		VirtualHosts: []*envoy_config_route_v3.VirtualHost{virtualHost},
	}

	routeBytes, err := proto.Marshal(&routeConfig)
	if err != nil {
		return v2.XDSResource{}, err
	}

	return v2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.RouteTypeURL,
			Value:   routeBytes,
		},
	}, nil
}

// getSocketOptions returns socket options for downstream connection.
// Currently, only TPC keep-alive related options are specified.
//
// Related references:
//  - https://man7.org/linux/man-pages/man7/tcp.7.html
//  - https://github.com/envoyproxy/envoy/issues/3634
func getSocketOptions(ingress *slim_networkingv1.Ingress) []*envoy_config_core_v3.SocketOption {
	tcpKeepAliveEnabled := annotations.GetAnnotationTCPKeepAliveEnabled(ingress)
	if tcpKeepAliveEnabled == 0 {
		return nil
	}
	return []*envoy_config_core_v3.SocketOption{
		{
			Description: "Enable TCP keep-alive, annotation io.cilium/tcp-keep-alive. (default to enabled)",
			Level:       syscall.SOL_SOCKET,
			Name:        syscall.SO_KEEPALIVE,
			Value: &envoy_config_core_v3.SocketOption_IntValue{
				IntValue: tcpKeepAliveEnabled,
			},
			State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
		},
		{
			Description: "TCP keep-alive idle time (in seconds). Annotation io.cilium/tcp-keep-alive-idle (defaults to 10s)",
			Level:       syscall.IPPROTO_TCP,
			Name:        syscall.TCP_KEEPIDLE,
			Value: &envoy_config_core_v3.SocketOption_IntValue{
				IntValue: annotations.GetAnnotationTCPKeepAliveIdle(ingress),
			},
			State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
		},
		{
			Description: "TCP keep-alive probe intervals (in seconds). Annotation io.cilium/tcp-keep-alive-probe-interval (defaults to 5s)",
			Level:       syscall.IPPROTO_TCP,
			Name:        syscall.TCP_KEEPINTVL,
			Value: &envoy_config_core_v3.SocketOption_IntValue{
				IntValue: annotations.GetAnnotationTCPKeepAliveProbeInterval(ingress),
			},
			State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
		},
		{
			Description: "TCP keep-alive probe max failures. Annotation io.cilium/tcp-keep-alive-probe-max-failures (defaults to 10)",
			Level:       syscall.IPPROTO_TCP,
			Name:        syscall.TCP_KEEPCNT,
			Value: &envoy_config_core_v3.SocketOption_IntValue{
				IntValue: annotations.GetAnnotationTCPKeepAliveProbeMaxFailures(ingress),
			},
			State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
		},
	}
}

func tlsEnabled(ingress *slim_networkingv1.Ingress) bool {
	return len(ingress.Spec.TLS) > 0
}

func getServiceFrontEndPort(sbe *slim_networkingv1.IngressServiceBackend) string {
	// As per Ingress spec, A port name or port number is required for a IngressServiceBackend.
	if sbe.Port.Number != 0 {
		return strconv.Itoa(int(sbe.Port.Number))
	}
	return sbe.Port.Name
}

func getClusterNameWithPort(namespace string, sbe *slim_networkingv1.IngressServiceBackend) string {
	return fmt.Sprintf("%s/%s:%s", namespace, sbe.Name, getServiceFrontEndPort(sbe))
}

func sortAndUnique(arr []string) []string {
	m := map[string]struct{}{}
	for _, s := range arr {
		m[s] = struct{}{}
	}

	var res []string
	for k := range m {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}
