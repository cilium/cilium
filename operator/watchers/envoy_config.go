// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package watchers

import (
	"context"
	"fmt"

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
	v1 "k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
)

func getResourceNameForIngress(ingress *slim_networkingv1.Ingress) string {
	return ciliumIngressPrefix + ingress.Namespace + "-" + ingress.Name
}

func (ic *ingressController) getSecret(namespace, name string) (string, string, error) {
	secret := v1.Secret{}
	err := k8s.Client().CoreV1().RESTClient().Get().Resource("secrets").Namespace(namespace).Name(name).Do(context.Background()).Into(&secret)
	if err != nil {
		return "", "", fmt.Errorf("failied to get secret %s/%s: %v", namespace, name, err)
	}
	ic.logger.WithField("data-fields", secret.Data).Info("Loaded secret. amazing")
	ic.logger.WithField("data-string-fields", secret.StringData).Info("Loaded secret. amazing")
	var tlsKey, tlsCrt []byte
	var ok bool
	if tlsKey, ok = secret.Data["tls.key"]; !ok {
		return "", "", fmt.Errorf("missing tls.key field in secret: %s/%s", namespace, name)
	}
	if tlsCrt, ok = secret.Data["tls.crt"]; !ok {
		return "", "", fmt.Errorf("missing tls.crt field in secret: %s/%s", namespace, name)
	}
	return string(tlsCrt), string(tlsKey), nil
}

func (ic *ingressController) getTLS(ingress *slim_networkingv1.Ingress) (map[string]*envoy_config_core_v3.TransportSocket, error) {
	tls := make(map[string]*envoy_config_core_v3.TransportSocket)
	for _, tlsConfig := range ingress.Spec.TLS {
		crt, key, err := ic.getSecret(ingress.Namespace, tlsConfig.SecretName)
		if err != nil {
			return nil, err
		}
		for _, host := range tlsConfig.Hosts {
			downStreamContext := envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
				CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
					TlsCertificates: []*envoy_extensions_transport_sockets_tls_v3.TlsCertificate{
						{
							CertificateChain: &envoy_config_core_v3.DataSource{
								Specifier: &envoy_config_core_v3.DataSource_InlineString{
									InlineString: crt,
								},
							},
							PrivateKey: &envoy_config_core_v3.DataSource{
								Specifier: &envoy_config_core_v3.DataSource_InlineString{
									InlineString: key,
								},
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
				Name: "tls",
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

func (ic *ingressController) amazingIngressControllerBusinessLogic(ingress *slim_networkingv1.Ingress) (*v2alpha1.CiliumEnvoyConfig, error) {
	backendServices := getBackendServices(ingress)
	resources, err := ic.getResources(ingress, backendServices)
	if err != nil {
		return nil, err
	}
	return &v2alpha1.CiliumEnvoyConfig{
		TypeMeta: v1meta.TypeMeta{
			Kind:       v2alpha1.CECKindDefinition,
			APIVersion: "cilium.io/v2alpha1",
		},
		ObjectMeta: v1meta.ObjectMeta{
			Name: getResourceNameForIngress(ingress),
		},
		Spec: v2alpha1.CiliumEnvoyConfigSpec{
			Services: []*v2alpha1.ServiceListener{
				{
					Name:      getServiceNameForIngress(ingress),
					Namespace: ingress.Namespace,
					Listener:  getResourceNameForIngress(ingress),
				},
			},
			BackendServices: backendServices,
			// TODO(michi) what is this
			// Ingress:         true,
			Resources: resources,
		},
	}, nil
}

func getBackendServices(ingress *slim_networkingv1.Ingress) []*v2alpha1.Service {
	services := make(map[string]struct{})
	for _, rule := range ingress.Spec.Rules {
		for _, path := range rule.HTTP.Paths {
			services[path.Backend.Service.Name] = struct{}{}
		}
	}
	var backendServices []*v2alpha1.Service
	for service := range services {
		backendServices = append(backendServices, &v2alpha1.Service{
			Namespace: ingress.Namespace,
			Name:      service,
		})
	}
	return backendServices
}

func (ic *ingressController) getResources(ingress *slim_networkingv1.Ingress, backendServices []*v2alpha1.Service) ([]v2alpha1.XDSResource, error) {
	var resources []v2alpha1.XDSResource
	tls, err := ic.getTLS(ingress)
	if err != nil {
		ic.logger.WithError(err).Warn("Failed to get secret for ingress")
	}
	listener, err := getListenerResource(ingress, tls)
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

func getListenerResource(ingress *slim_networkingv1.Ingress, tls map[string]*envoy_config_core_v3.TransportSocket) (v2alpha1.XDSResource, error) {
	connectionManager := envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager{
		StatPrefix: ingress.Name,
		RouteSpecifier: &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager_Rds{
			Rds: &envoy_extensions_filters_network_http_connection_manager_v3.Rds{
				ConfigSource:    nil,
				RouteConfigName: getResourceNameForIngress(ingress) + "_route",
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
		Name: getResourceNameForIngress(ingress),
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
		// just take the first one for now
		domain := ingress.Spec.TLS[0].Hosts[0]
		tlsconf := tls[domain]
		if tlsconf != nil {
			listener.FilterChains[0].TransportSocket = tlsconf
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

func getVirtualHost(ingress *slim_networkingv1.Ingress, rule slim_networkingv1.IngressRule) *envoy_config_route_v3.VirtualHost {
	var routes []*envoy_config_route_v3.Route
	for _, path := range rule.HTTP.Paths {
		route := envoy_config_route_v3.Route{
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
					Prefix: path.Path,
				},
			},
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
	domains := []string{"*"}
	if rule.Host != "" {
		domains = []string{
			rule.Host,
			// match authority header with port (e.g. "example.com:80")
			rule.Host + ":*",
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
		Name:         getResourceNameForIngress(ingress) + "_route",
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
