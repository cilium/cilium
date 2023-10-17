// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	grpcStatsv3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/grpc_stats/v3"
	grpcWebv3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/grpc_web/v3"
	httpRouterv3 "github.com/cilium/proxy/go/envoy/extensions/filters/http/router/v3"
	httpConnectionManagerv3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

type HttpConnectionManagerMutator func(*httpConnectionManagerv3.HttpConnectionManager) *httpConnectionManagerv3.HttpConnectionManager

// NewHTTPConnectionManager returns a new HTTP connection manager filter with the given name and route.
// Mutation functions can be passed to modify the filter based on the caller's needs.
func NewHTTPConnectionManager(name, routeName string, mutationFunc ...HttpConnectionManagerMutator) (ciliumv2.XDSResource, error) {
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
	}

	// Apply mutation functions for customizing the connection manager.
	for _, fn := range mutationFunc {
		connectionManager = fn(connectionManager)
	}

	connectionManagerBytes, err := proto.Marshal(connectionManager)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}

	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.HttpConnectionManagerTypeURL,
			Value:   connectionManagerBytes,
		},
	}, nil
}

func WithXffNumTrustedHops() func(*httpConnectionManagerv3.HttpConnectionManager) *httpConnectionManagerv3.HttpConnectionManager {
	return func(connectionManager *httpConnectionManagerv3.HttpConnectionManager) *httpConnectionManagerv3.HttpConnectionManager {
		connectionManager.XffNumTrustedHops = operatorOption.Config.IngressProxyXffNumTrustedHops
		return connectionManager
	}
}
