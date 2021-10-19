// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package watchers

import (
	"fmt"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_extensions_filters_network_http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
)

func amazingIngressControllerBusinessLogic(ingress *slim_networkingv1.Ingress) (*v2alpha1.CiliumEnvoyConfig, error) {
	backendServices := getBackendServices(ingress)
	resources, err := getResources(ingress, backendServices)
	if err != nil {
		return nil, err
	}
	return &v2alpha1.CiliumEnvoyConfig{
		TypeMeta: v1meta.TypeMeta{
			Kind:       v2alpha1.CECKindDefinition,
			APIVersion: "cilium.io/v2alpha1",
		},
		ObjectMeta: v1meta.ObjectMeta{
			Name: ingress.Name,
		},
		Spec: v2alpha1.CiliumEnvoyConfigSpec{
			Services: []*v2alpha1.ServiceListener{
				{
					Name:      getServiceNameForIngress(ingress),
					Namespace: ingress.Namespace,
					Listener:  ingress.Name,
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
	connectionManager := envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager{
		StatPrefix: ingress.Name,
		RouteSpecifier: &envoy_extensions_filters_network_http_connection_manager_v3.HttpConnectionManager_Rds{
			Rds: &envoy_extensions_filters_network_http_connection_manager_v3.Rds{
				ConfigSource:    nil,
				RouteConfigName: "ingress_route",
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
		Name: ingress.Name,
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
	hostname := "*"
	if rule.Host != "" {
		hostname = rule.Host
	}
	return &envoy_config_route_v3.VirtualHost{
		Name:    "ingress_route",
		Domains: []string{hostname},
		Routes:  routes,
	}
}

func getRouteConfigurationResource(ingress *slim_networkingv1.Ingress) (v2alpha1.XDSResource, error) {
	var virtualhosts []*envoy_config_route_v3.VirtualHost
	for _, rule := range ingress.Spec.Rules {
		virtualhosts = append(virtualhosts, getVirtualHost(ingress, rule))
	}
	routeConfig := envoy_config_route_v3.RouteConfiguration{
		Name:         "ingress_route",
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
