// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"slices"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	overridehostv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/load_balancing_policies/override_host/v3"
	httpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestCECTranslator_InferenceAndExtensionRefCoexistence(t *testing.T) {
	shared := model.Backend{Namespace: "ns", Name: "shared", Port: &model.BackendPort{Port: 8080}}
	processorBackend := model.Backend{Namespace: "ns", Name: "processor", Port: &model.BackendPort{Port: 9000}}
	epp := &model.EndpointPicker{Namespace: "ns", Name: "shared", Port: 8080, FailureMode: "FailOpen", AppProtocol: AppProtocolH2C}
	otherEPP := &model.EndpointPicker{Namespace: "ns", Name: "shared", Port: 8080, FailureMode: "FailClose"}
	pool := model.Backend{Namespace: "ns", Name: "pool-shadow", Port: &model.BackendPort{Port: 8000}, EndpointPicker: epp}
	otherPool := model.Backend{Namespace: "ns", Name: "other-pool-shadow", Port: &model.BackendPort{Port: 8001}, EndpointPicker: otherEPP}
	grpcAuth := &model.HTTPExternalAuthFilter{Backend: shared, Protocol: model.ExternalAuthProtocolGRPC}
	httpAuth := &model.HTTPExternalAuthFilter{Backend: shared, Protocol: model.ExternalAuthProtocolHTTP, PathPrefix: "/check"}

	makeProcessor := func(name string, backend model.Backend, failOpen bool) model.ExtensionRefFilter {
		config := toAny(&extprocv3.ExternalProcessor{
			GrpcService: &corev3.GrpcService{
				TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
						ClusterName: getExtProcClusterName(backend.Namespace, backend.Name, backend.Port.GetPort()),
						Authority:   backend.Name + ":" + backend.Port.GetPort(),
					},
				},
			},
			FailureModeAllow: failOpen,
			MessageTimeout:   durationpb.New(17 * time.Second),
			ProcessingMode: &extprocv3.ProcessingMode{
				RequestHeaderMode:  extprocv3.ProcessingMode_SEND,
				ResponseHeaderMode: extprocv3.ProcessingMode_SEND,
				RequestBodyMode:    extprocv3.ProcessingMode_BUFFERED,
			},
		})
		return model.ExtensionRefFilter{
			Name:    model.ExtProcFilterNamePrefix + "/ns/" + name,
			TypeURL: config.TypeUrl,
			// Unknown protobuf fields must survive translation, too.
			Config:  append(config.Value, 0xf8, 0x07, 0x01),
			Backend: &backend,
		}
	}
	processor := makeProcessor("first", shared, false)
	secondProcessor := makeProcessor("second", processorBackend, true)

	m := &model.Model{HTTP: []model.HTTPListener{{
		Port: 80, Hostname: "example.com",
		Routes: []model.HTTPRoute{
			{PathMatch: model.StringMatch{Exact: "/inference"}, Backends: []model.Backend{pool}},
			{PathMatch: model.StringMatch{Exact: "/processing"}, Backends: []model.Backend{shared}, ExtensionRefFilters: []model.ExtensionRefFilter{processor}},
			{PathMatch: model.StringMatch{Exact: "/combined"}, Backends: []model.Backend{pool}, ExtensionRefFilters: []model.ExtensionRefFilter{processor, secondProcessor}, ExternalAuth: grpcAuth},
			{PathMatch: model.StringMatch{Exact: "/authorized"}, Backends: []model.Backend{shared}, ExternalAuth: httpAuth},
			{PathMatch: model.StringMatch{Exact: "/normal"}, Backends: []model.Backend{shared}},
			{PathMatch: model.StringMatch{Exact: "/other-inference"}, Backends: []model.Backend{otherPool}},
			{PathMatch: model.StringMatch{Exact: "/unavailable"}, Backends: []model.Backend{pool}, ExtensionRefFilters: []model.ExtensionRefFilter{processor, secondProcessor}, ExternalAuth: grpcAuth, DirectResponse: &model.DirectResponse{StatusCode: 500}},
		},
	}}}
	cec, err := (&cecTranslator{}).Translate("ns", "gateway", m)
	require.NoError(t, err)
	require.Equal(t, []*ciliumv2.Service{
		{Namespace: "ns", Name: "other-pool-shadow"},
		{Namespace: "ns", Name: "pool-shadow"},
		{Namespace: "ns", Name: "processor", Ports: []string{"9000"}},
		{Namespace: "ns", Name: "shared", Ports: []string{"8080"}},
	}, cec.Spec.BackendServices, "pool services must remain portless while external backends retain their ports")

	clusters := map[string]*clusterv3.Cluster{}
	routes := map[string]*routev3.Route{}
	var hcm *hcmv3.HttpConnectionManager
	for _, resource := range cec.Spec.Resources {
		switch resource.GetTypeUrl() {
		case envoy.ListenerTypeURL:
			listener := &listenerv3.Listener{}
			require.NoError(t, resource.UnmarshalTo(listener))
			for _, chain := range listener.GetFilterChains() {
				for _, filter := range chain.GetFilters() {
					if filter.GetName() == httpConnectionManagerType {
						require.Nil(t, hcm, "expected one HTTP connection manager")
						hcm = &hcmv3.HttpConnectionManager{}
						require.NoError(t, filter.GetTypedConfig().UnmarshalTo(hcm))
					}
				}
			}
		case envoy.RouteTypeURL:
			rc := &routev3.RouteConfiguration{}
			require.NoError(t, resource.UnmarshalTo(rc))
			for _, host := range rc.GetVirtualHosts() {
				for _, route := range host.GetRoutes() {
					path := route.GetMatch().GetPath()
					require.NotContains(t, routes, path)
					routes[path] = route
				}
			}
		case envoy.ClusterTypeURL:
			cluster := &clusterv3.Cluster{}
			require.NoError(t, resource.UnmarshalTo(cluster))
			require.NotContains(t, clusters, cluster.Name, "cluster resources must be deduplicated")
			clusters[cluster.Name] = cluster
		}
	}
	require.NotNil(t, hcm)
	require.Equal(t, "listener-insecure", hcm.GetRds().GetRouteConfigName())
	require.Len(t, routes, 7)
	require.Len(t, clusters, 8)

	filterIndex := map[string]int{}
	for index, filter := range hcm.GetHttpFilters() {
		require.NotContains(t, filterIndex, filter.Name, "filter instances must be deduplicated")
		filterIndex[filter.Name] = index
	}
	eppFilter := ExtProcFilterName(getEPPClusterName(epp))
	otherEPPFilter := ExtProcFilterName(getEPPClusterName(otherEPP))
	grpcAuthFilter := ExtAuthzFilterName(extAuthzFilterKey(grpcAuth))
	httpAuthFilter := ExtAuthzFilterName(extAuthzFilterKey(httpAuth))
	externalFilters := []string{processor.Name, secondProcessor.Name, eppFilter, otherEPPFilter, grpcAuthFilter, httpAuthFilter}
	for _, name := range append(slices.Clone(externalFilters), "envoy.filters.http.router") {
		require.Contains(t, filterIndex, name)
	}
	require.Less(t, filterIndex[processor.Name], filterIndex[secondProcessor.Name], "declared ExtensionRef order must survive")
	for _, name := range externalFilters[:4] {
		for _, authName := range externalFilters[4:] {
			require.Less(t, filterIndex[name], filterIndex[authName], "all external processing must precede authorization")
		}
	}
	for _, name := range externalFilters {
		require.Less(t, filterIndex[name], filterIndex["envoy.filters.http.router"])
	}
	for _, filter := range []model.ExtensionRefFilter{processor, secondProcessor} {
		config := hcm.GetHttpFilters()[filterIndex[filter.Name]].GetTypedConfig()
		require.Equal(t, filter.TypeURL, config.TypeUrl)
		require.Equal(t, filter.Config, config.Value, "arbitrary ext_proc configuration must not be rebuilt as an EPP config")
		decoded := &extprocv3.ExternalProcessor{}
		require.NoError(t, config.UnmarshalTo(decoded))
		require.Contains(t, clusters, decoded.GetGrpcService().GetEnvoyGrpc().GetClusterName())
	}
	for _, picker := range []*model.EndpointPicker{epp, otherEPP} {
		config := &extprocv3.ExternalProcessor{}
		require.NoError(t, hcm.GetHttpFilters()[filterIndex[ExtProcFilterName(getEPPClusterName(picker))]].GetTypedConfig().UnmarshalTo(config))
		require.Equal(t, getEPPClusterName(picker), config.GetGrpcService().GetEnvoyGrpc().GetClusterName())
		require.Equal(t, picker.FailureMode == "FailOpen", config.GetFailureModeAllow())
		require.Equal(t, extprocv3.ProcessingMode_FULL_DUPLEX_STREAMED, config.GetProcessingMode().GetRequestBodyMode())
	}

	for path, active := range map[string][]string{
		"/inference":       {eppFilter},
		"/processing":      {processor.Name},
		"/combined":        {processor.Name, secondProcessor.Name, eppFilter, grpcAuthFilter},
		"/authorized":      {httpAuthFilter},
		"/normal":          nil,
		"/other-inference": {otherEPPFilter},
		"/unavailable":     nil,
	} {
		t.Run(path, func(t *testing.T) {
			config := routes[path].GetTypedPerFilterConfig()
			require.Len(t, config, len(externalFilters)-len(active))
			for _, name := range externalFilters {
				if slices.Contains(active, name) {
					require.NotContains(t, config, name, "matching filter must remain enabled")
					continue
				}
				require.Contains(t, config, name, "unrelated filter must be explicitly disabled")
				if name == grpcAuthFilter || name == httpAuthFilter {
					perRoute := &extauthzv3.ExtAuthzPerRoute{}
					require.NoError(t, config[name].UnmarshalTo(perRoute))
					require.True(t, perRoute.GetDisabled())
				} else {
					perRoute := &extprocv3.ExtProcPerRoute{}
					require.NoError(t, config[name].UnmarshalTo(perRoute))
					require.True(t, perRoute.GetDisabled())
				}
			}
		})
	}
	require.Equal(t, uint32(500), routes["/unavailable"].GetDirectResponse().GetStatus())
	for _, backend := range []model.Backend{pool, otherPool} {
		name := getClusterName(backend.Namespace, backend.Name, backend.Port.GetPort())
		require.Contains(t, clusters, name)
		cluster := clusters[name]
		require.Equal(t, clusterv3.Cluster_EDS, cluster.GetType())
		require.Equal(t, backend.Namespace+"/"+backend.Name, cluster.GetEdsClusterConfig().GetServiceName())
		policy := &overridehostv3.OverrideHost{}
		require.NoError(t, cluster.GetLoadBalancingPolicy().GetPolicies()[0].GetTypedExtensionConfig().GetTypedConfig().UnmarshalTo(policy))
		require.Equal(t, "x-gateway-destination-endpoint", policy.GetOverrideHostSources()[0].GetHeader())
		require.Equal(t, "envoy.load_balancing_policies.round_robin", policy.GetFallbackPolicy().GetPolicies()[0].GetTypedExtensionConfig().GetName())
	}
	require.Equal(t, getClusterName("ns", pool.Name, "8000"), routes["/combined"].GetRoute().GetCluster())
	require.Equal(t, getClusterName("ns", shared.Name, "8080"), routes["/normal"].GetRoute().GetCluster())

	for name, cluster := range clusters {
		opts := &httpv3.HttpProtocolOptions{}
		require.NoError(t, cluster.TypedExtensionProtocolOptions[httpProtocolOptionsType].UnmarshalTo(opts))
		switch name {
		case getClusterName("ns", "shared", "8080"), getHTTPExtAuthClusterName("ns", "shared", "8080"):
			require.NotNil(t, opts.GetUseDownstreamProtocolConfig())
		case getClusterName("ns", otherPool.Name, "8001"):
			require.NotNil(t, opts.GetExplicitHttpConfig().GetHttpProtocolOptions())
		default:
			require.NotNil(t, opts.GetExplicitHttpConfig().GetHttp2ProtocolOptions())
		}
	}
	for _, picker := range []*model.EndpointPicker{epp, otherEPP} {
		cluster := clusters[getEPPClusterName(picker)]
		require.NotNil(t, cluster.GetTransportSocket(), "EPP must retain its upstream TLS configuration")
		require.Equal(t, "ns/shared:8080", cluster.GetEdsClusterConfig().GetServiceName())
	}
}

func TestCECTranslator_ExtensionRefBackendDoesNotRepopulateInferenceShadowPorts(t *testing.T) {
	pool := model.Backend{
		Namespace: "ns", Name: "pool-shadow", Port: &model.BackendPort{Port: 8000},
		EndpointPicker: &model.EndpointPicker{Namespace: "ns", Name: "epp", Port: 9002},
	}
	filterBackend := model.Backend{Namespace: "ns", Name: "pool-shadow", Port: &model.BackendPort{Port: 8001}}
	poolRoute := model.HTTPRoute{Backends: []model.Backend{pool}}
	filterRoute := model.HTTPRoute{ExtensionRefFilters: []model.ExtensionRefFilter{{Backend: &filterBackend}}}
	for _, routes := range [][]model.HTTPRoute{{poolRoute, filterRoute}, {filterRoute, poolRoute}} {
		backends, err := (&cecTranslator{}).desiredBackendServices(&model.Model{HTTP: []model.HTTPListener{{Routes: routes}}})
		require.NoError(t, err)
		require.Equal(t, []*ciliumv2.Service{
			{Namespace: "ns", Name: "epp", Ports: []string{"9002"}},
			{Namespace: "ns", Name: "pool-shadow"},
		}, backends)
	}
}
