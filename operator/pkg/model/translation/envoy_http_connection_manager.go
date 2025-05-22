// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	grpcStatsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_stats/v3"
	grpcWebv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_web/v3"
	httpRouterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

type HttpConnectionManagerMutator func(*httpConnectionManagerv3.HttpConnectionManager) *httpConnectionManagerv3.HttpConnectionManager

func WithInternalAddressConfig(enableIpv4, enableIpv6 bool) HttpConnectionManagerMutator {
	return func(hcm *httpConnectionManagerv3.HttpConnectionManager) *httpConnectionManagerv3.HttpConnectionManager {
		hcm.InternalAddressConfig = &httpConnectionManagerv3.HttpConnectionManager_InternalAddressConfig{
			UnixSockets: false,
			CidrRanges:  envoy.GetInternalListenerCIDRs(enableIpv4, enableIpv6),
		}
		return hcm
	}
}

// httpConnectionManagerMutators returns a list of mutator functions for customizing the HTTP connection manager.
func (i *cecTranslator) httpConnectionManagerMutators() []HttpConnectionManagerMutator {
	return []HttpConnectionManagerMutator{
		WithInternalAddressConfig(i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled),
	}
}

// desiredHTTPConnectionManager returns a new HTTP connection manager filter with the given name and route.
func (i *cecTranslator) desiredHTTPConnectionManager(name, routeName string) (ciliumv2.XDSResource, error) {
	connectionManager := &httpConnectionManagerv3.HttpConnectionManager{
		StatPrefix: name,
		RouteSpecifier: &httpConnectionManagerv3.HttpConnectionManager_Rds{
			Rds: &httpConnectionManagerv3.Rds{RouteConfigName: routeName},
		},
		UseRemoteAddress: &wrapperspb.BoolValue{Value: true},
		SkipXffAppend:    false,
		HttpFilters: []*httpConnectionManagerv3.HttpFilter{
			{
				Name: "envoy.filters.http.grpc_web",
				ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
					TypedConfig: toAny(&grpcWebv3.GrpcWeb{}),
				},
			},
			{
				Name: "envoy.filters.http.grpc_stats",
				ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
					TypedConfig: toAny(&grpcStatsv3.FilterConfig{
						EmitFilterState:     true,
						EnableUpstreamStats: true,
					}),
				},
			},
			{
				Name: "envoy.filters.http.router",
				ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
					TypedConfig: toAny(&httpRouterv3.Router{}),
				},
			},
		},
		UpgradeConfigs: []*httpConnectionManagerv3.HttpConnectionManager_UpgradeConfig{
			{UpgradeType: "websocket"},
		},
		CommonHttpProtocolOptions: &envoy_config_core.HttpProtocolOptions{
			MaxStreamDuration: &durationpb.Duration{
				Seconds: 0,
			},
		},
	}

	// Apply mutation functions for customizing the connection manager.
	for _, fn := range i.httpConnectionManagerMutators() {
		connectionManager = fn(connectionManager)
	}

	return toXdsResource(connectionManager, envoy.HttpConnectionManagerTypeURL)
}
