// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

type RouteConfigurationMutator func(*envoy_config_route_v3.RouteConfiguration) *envoy_config_route_v3.RouteConfiguration

// NewRouteConfiguration returns a new route configuration for a given list of http routes.
func NewRouteConfiguration(name string, virtualhosts []*envoy_config_route_v3.VirtualHost, mutators ...RouteConfigurationMutator) (ciliumv2.XDSResource, error) {
	routeConfig := &envoy_config_route_v3.RouteConfiguration{
		Name:         name,
		VirtualHosts: virtualhosts,
	}

	// Apply mutation functions for customizing the route configuration.
	for _, fn := range mutators {
		routeConfig = fn(routeConfig)
	}

	routeBytes, err := proto.Marshal(routeConfig)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}

	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.RouteTypeURL,
			Value:   routeBytes,
		},
	}, nil
}
