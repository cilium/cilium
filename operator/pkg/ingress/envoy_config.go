// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package ingress

import (
	"fmt"
	"net"
	"sort"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_extensions_filters_network_http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	envoy_config_upstream "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
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
		cache.NewListWatchFromClient(k8s.CiliumClient().CiliumV2alpha1().RESTClient(), v2alpha1.CECPluralName, corev1.NamespaceAll, fields.Everything()),
		&v2alpha1.CiliumEnvoyConfig{},
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
func (em *envoyConfigManager) getByKey(key string) (*v2alpha1.CiliumEnvoyConfig, bool, error) {
	objFromCache, exists, err := em.store.GetByKey(key)
	if objFromCache == nil || !exists || err != nil {
		return nil, exists, err
	}
	envoyConfig, ok := objFromCache.(*v2alpha1.CiliumEnvoyConfig)
	if !ok {
		return nil, exists, fmt.Errorf("got invalid object from cache")
	}
	return envoyConfig, exists, err
}

func getCECNameForIngress(ingress *slim_networkingv1.Ingress) string {
	return ciliumIngressPrefix + ingress.Namespace + "-" + ingress.Name
}

func getTransportSocket(ingress *slim_networkingv1.Ingress) (map[string]*envoy_config_core_v3.TransportSocket, error) {
	tls := make(map[string]*envoy_config_core_v3.TransportSocket)
	for _, tlsConfig := range ingress.Spec.TLS {
		for _, host := range tlsConfig.Hosts {
			downStreamContext := envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
				CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
					TlsCertificateSdsSecretConfigs: []*envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig{
						{
							Name: fmt.Sprintf("%s/%s", ingress.Namespace, tlsConfig.SecretName),
							SdsConfig: &envoy_config_core_v3.ConfigSource{
								ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_ApiConfigSource{
									ApiConfigSource: &envoy_config_core_v3.ApiConfigSource{
										ApiType:             envoy_config_core_v3.ApiConfigSource_GRPC,
										TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
										GrpcServices: []*envoy_config_core_v3.GrpcService{
											{
												TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
													EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
														ClusterName: "xds-grpc-cilium",
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
							Name: fmt.Sprintf("%s/%s", ingress.Namespace, tlsConfig.SecretName),
							SdsConfig: &envoy_config_core_v3.ConfigSource{
								ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_ApiConfigSource{
									ApiConfigSource: &envoy_config_core_v3.ApiConfigSource{
										ApiType:             envoy_config_core_v3.ApiConfigSource_GRPC,
										TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
										GrpcServices: []*envoy_config_core_v3.GrpcService{
											{
												TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
													EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
														ClusterName: "xds-grpc-cilium",
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
					AlpnProtocols:    nil,
					CustomHandshaker: nil,
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
						TypeUrl: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
						Value:   upstreamContextBytes,
					},
				},
			}
		}
	}
	return tls, nil
}

func getEnvoyConfigForIngress(ingress *slim_networkingv1.Ingress) (*v2alpha1.CiliumEnvoyConfig, error) {
	backendServices := getBackendServices(ingress)
	resources, err := getResources(ingress, backendServices)
	if err != nil {
		return nil, err
	}
	return &v2alpha1.CiliumEnvoyConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       v2alpha1.CECKindDefinition,
			APIVersion: v2alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: getCECNameForIngress(ingress),
		},
		Spec: v2alpha1.CiliumEnvoyConfigSpec{
			Services: []*v2alpha1.ServiceListener{
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

func getBackendServices(ingress *slim_networkingv1.Ingress) []*v2alpha1.Service {
	var sortedServiceNames []string
	if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
		sortedServiceNames = append(sortedServiceNames, ingress.Spec.DefaultBackend.Service.Name)
	}
	for _, rule := range ingress.Spec.Rules {
		for _, path := range rule.HTTP.Paths {
			sortedServiceNames = append(sortedServiceNames, path.Backend.Service.Name)
		}
	}
	sort.Strings(sortedServiceNames)

	var backendServices []*v2alpha1.Service
	for _, name := range sortedServiceNames {
		backendServices = append(backendServices, &v2alpha1.Service{
			Namespace: ingress.Namespace,
			Name:      name,
		})
	}
	return backendServices
}

func getResources(ingress *slim_networkingv1.Ingress, backendServices []*v2alpha1.Service) ([]v2alpha1.XDSResource, error) {
	var resources []v2alpha1.XDSResource
	listener, err := getListenerResource(ingress)
	if err != nil {
		return nil, err
	}
	resources = append(resources, listener)
	routeConfig, err := getRouteConfigurationResource(ingress)
	if err != nil {
		return nil, err
	}
	resources = append(resources, routeConfig)
	clusters, err := getClusterResources(backendServices)
	if err != nil {
		return nil, err
	}
	resources = append(resources, clusters...)
	return resources, nil
}

func getListenerResource(ingress *slim_networkingv1.Ingress) (v2alpha1.XDSResource, error) {
	tls, err := getTransportSocket(ingress)
	if err != nil {
		log.WithError(err).Warn("Failed to get secret for ingress")
	}

	connectionManager := envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager{
		StatPrefix: ingress.Name,
		RouteSpecifier: &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager_Rds{
			Rds: &envoy_extensions_filters_network_http_connection_manager_v3.Rds{
				ConfigSource:    nil,
				RouteConfigName: getCECNameForIngress(ingress) + "_route",
			},
		},
		HttpFilters: []*envoy_extensions_filters_network_http_connection_manager_v3.HttpFilter{
			{Name: "envoy.filters.http.router"},
		},
	}
	connectionManagerBytes, err := proto.Marshal(&connectionManager)
	if err != nil {
		return v2alpha1.XDSResource{}, err
	}
	listener := envoy_config_listener.Listener{
		Name: getCECNameForIngress(ingress),
		FilterChains: []*envoy_config_listener.FilterChain{
			{
				Filters: []*envoy_config_listener.Filter{
					{
						Name: "envoy.filters.network.http_connection_manager",
						ConfigType: &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: &anypb.Any{
								TypeUrl: "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
								Value:   connectionManagerBytes,
							},
						},
					},
				},
			},
		},
	}
	if len(ingress.Spec.TLS) > 0 {
		// TODO(tam) extend to list of tls
		// just take the first one for now
		if len(ingress.Spec.TLS[0].Hosts) > 0 {
			domain := ingress.Spec.TLS[0].Hosts[0]
			tlsConf := tls[domain]
			if tlsConf != nil {
				listener.FilterChains[0].TransportSocket = tlsConf
			}
		}
	}
	listenerBytes, err := proto.Marshal(&listener)
	if err != nil {
		return v2alpha1.XDSResource{}, err
	}
	return v2alpha1.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.ListenerTypeURL,
			Value:   listenerBytes,
		},
	}, nil
}

func getClusterResources(backendServices []*v2alpha1.Service) ([]v2alpha1.XDSResource, error) {
	var resources []v2alpha1.XDSResource
	for _, service := range backendServices {
		cluster := envoy_config_cluster_v3.Cluster{
			Name:           fmt.Sprintf("%s/%s", service.Namespace, service.Name),
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
				ConsecutiveLocalOriginFailure:  &wrapperspb.UInt32Value{Value: 2},
			},
			ClusterDiscoveryType: &envoy_config_cluster_v3.Cluster_Type{
				Type: envoy_config_cluster_v3.Cluster_EDS,
			},
		}
		clusterBytes, err := proto.Marshal(&cluster)
		if err != nil {
			return nil, err
		}
		resources = append(resources, v2alpha1.XDSResource{
			Any: &anypb.Any{
				TypeUrl: envoy.ClusterTypeURL,
				Value:   clusterBytes,
			},
		})
	}
	return resources, nil
}

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		panic(err.Error())
	}
	return a
}

func getRouteMatch(ingressPath slim_networkingv1.HTTPIngressPath) *envoy_config_route_v3.RouteMatch {
	if ingressPath.PathType == nil || *ingressPath.PathType == slim_networkingv1.PathTypeImplementationSpecific ||
		*ingressPath.PathType == slim_networkingv1.PathTypePrefix {
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
				Prefix: ingressPath.Path,
			},
		}
	}
	if *ingressPath.PathType == slim_networkingv1.PathTypeExact {
		return &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
				Path: ingressPath.Path,
			},
		}
	}
	return nil
}

func getVirtualHost(ingress *slim_networkingv1.Ingress, rule slim_networkingv1.IngressRule) *envoy_config_route_v3.VirtualHost {
	var routes []*envoy_config_route_v3.Route
	for _, path := range rule.HTTP.Paths {
		route := envoy_config_route_v3.Route{
			Match: getRouteMatch(path),
			Action: &envoy_config_route_v3.Route_Route{
				Route: &envoy_config_route_v3.RouteAction{
					ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
						Cluster: fmt.Sprintf("%s/%s", ingress.Namespace, path.Backend.Service.Name),
					},
				},
			},
		}
		routes = append(routes, &route)
	}

	// The default backend route should be the last one
	if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
		route := envoy_config_route_v3.Route{
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
					Prefix: "/",
				},
			},
			Action: &envoy_config_route_v3.Route_Route{
				Route: &envoy_config_route_v3.RouteAction{
					ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
						Cluster: fmt.Sprintf("%s/%s", ingress.Namespace, ingress.Spec.DefaultBackend.Service.Name),
					},
				},
			},
		}
		routes = append(routes, &route)
	}

	domains := []string{"*"}
	if rule.Host != "" {
		domains = []string{
			rule.Host,
			// match authority header with port (e.g. "example.com:80")
			net.JoinHostPort(rule.Host, "*"),
		}
	}
	return &envoy_config_route_v3.VirtualHost{
		Name:    domains[0],
		Domains: domains,
		Routes:  routes,
	}
}

func getRouteConfigurationResource(ingress *slim_networkingv1.Ingress) (v2alpha1.XDSResource, error) {
	var virtualhosts []*envoy_config_route_v3.VirtualHost
	for _, rule := range ingress.Spec.Rules {
		virtualhosts = append(virtualhosts, getVirtualHost(ingress, rule))
	}
	routeConfig := envoy_config_route_v3.RouteConfiguration{
		Name:         getCECNameForIngress(ingress) + "_route",
		VirtualHosts: virtualhosts,
	}
	routeBytes, err := proto.Marshal(&routeConfig)
	if err != nil {
		return v2alpha1.XDSResource{}, err
	}
	return v2alpha1.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.RouteTypeURL,
			Value:   routeBytes,
		},
	}, nil
}
