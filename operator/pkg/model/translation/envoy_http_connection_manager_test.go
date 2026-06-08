// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	httpCORSv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/operator/pkg/model"
)

func Test_desiredHTTPConnectionManager(t *testing.T) {
	t.Run("no CORS filter enabled", func(t *testing.T) {
		i := &cecTranslator{}
		m := &model.Model{}
		res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
		require.NoError(t, err)

		httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
		err = proto.Unmarshal(res.Value, httpConnectionManager)

		require.NoError(t, err)

		require.Equal(t, "dummy-name", httpConnectionManager.StatPrefix)
		require.Equal(t, &httpConnectionManagerv3.HttpConnectionManager_Rds{
			Rds: &httpConnectionManagerv3.Rds{RouteConfigName: "dummy-route-name"},
		}, httpConnectionManager.GetRouteSpecifier())

		require.Len(t, httpConnectionManager.GetHttpFilters(), 3)
		require.Equal(t, "envoy.filters.http.grpc_web", httpConnectionManager.GetHttpFilters()[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[1].Name)
		require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[2].Name)

		require.Len(t, httpConnectionManager.GetUpgradeConfigs(), 1)
		require.Equal(t, "websocket", httpConnectionManager.GetUpgradeConfigs()[0].UpgradeType)
	})
	t.Run("CORS filter enabled", func(t *testing.T) {
		i := &cecTranslator{}
		m := &model.Model{HTTP: []model.HTTPListener{
			{
				Routes: []model.HTTPRoute{
					{
						CORS: &model.HTTPCORSFilter{AllowOrigins: []string{"*"}},
					},
				},
			},
		}}
		res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
		require.NoError(t, err)

		httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
		err = proto.Unmarshal(res.Value, httpConnectionManager)

		require.NoError(t, err)

		require.Equal(t, "dummy-name", httpConnectionManager.StatPrefix)
		require.Equal(t, &httpConnectionManagerv3.HttpConnectionManager_Rds{
			Rds: &httpConnectionManagerv3.Rds{RouteConfigName: "dummy-route-name"},
		}, httpConnectionManager.GetRouteSpecifier())

		require.Len(t, httpConnectionManager.GetHttpFilters(), 4)
		require.Equal(t, "envoy.filters.http.grpc_web", httpConnectionManager.GetHttpFilters()[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[1].Name)
		require.Equal(t, "envoy.filters.http.cors", httpConnectionManager.GetHttpFilters()[2].Name)
		require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[3].Name)

		require.Len(t, httpConnectionManager.GetUpgradeConfigs(), 1)
		require.Equal(t, "websocket", httpConnectionManager.GetUpgradeConfigs()[0].UpgradeType)
	})
	t.Run("access logs configured", func(t *testing.T) {
		i := &cecTranslator{}
		m := &model.Model{
			Telemetry: &model.Telemetry{
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetHTTP: {
						{
							Format: model.AccessLogsFormatText,
							Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
						},
					},
				},
			},
		}
		res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
		require.NoError(t, err)

		httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
		err = proto.Unmarshal(res.Value, httpConnectionManager)
		require.NoError(t, err)

		require.Len(t, httpConnectionManager.GetAccessLog(), 1)
		require.Equal(t, "envoy.access_loggers.stdout", httpConnectionManager.GetAccessLog()[0].GetName())
	})
}

func Test_getHTTPConnectionManagerHttpFilters(t *testing.T) {
	t.Run("no CORS filter enabled", func(t *testing.T) {
		m := &model.Model{}
		i := &cecTranslator{}
		res := i.getHTTPConnectionManagerHttpFilters(m)

		require.Len(t, res, 3)
		require.Equal(t, "envoy.filters.http.grpc_web", res[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", res[1].Name)
		require.Equal(t, "envoy.filters.http.router", res[2].Name)
	})
	t.Run("CORS filter enabled", func(t *testing.T) {
		m := &model.Model{HTTP: []model.HTTPListener{
			{
				Routes: []model.HTTPRoute{
					{
						CORS: &model.HTTPCORSFilter{AllowOrigins: []string{"*"}},
					},
				},
			},
		}}
		i := &cecTranslator{}
		res := i.getHTTPConnectionManagerHttpFilters(m)

		require.Len(t, res, 4)
		require.Equal(t, "envoy.filters.http.grpc_web", res[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", res[1].Name)
		require.Equal(t, "envoy.filters.http.cors", res[2].Name)
		require.Equal(t, "envoy.filters.http.router", res[3].Name)

	})
}

func Test_desiredHTTPConnectionManager_withExtAuthz(t *testing.T) {
	i := &cecTranslator{}
	m := &model.Model{
		HTTP: []model.HTTPListener{{
			Routes: []model.HTTPRoute{
				{
					ExternalAuth: &model.HTTPExternalAuthFilter{
						Backend:  model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
						Protocol: model.ExternalAuthProtocolGRPC,
					},
				},
				{
					ExternalAuth: &model.HTTPExternalAuthFilter{
						Backend:    model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
						Protocol:   model.ExternalAuthProtocolHTTP,
						PathPrefix: "/auth",
					},
				},
			},
		}},
	}
	authFilters := i.getUniqueAuthFilters(m)
	res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
	require.NoError(t, err)

	hcm := &httpConnectionManagerv3.HttpConnectionManager{}
	require.NoError(t, proto.Unmarshal(res.Value, hcm))

	// grpc_web, grpc_stats, ext_authz/grpc, ext_authz/http, router
	require.Len(t, hcm.GetHttpFilters(), 5)
	require.Equal(t, "envoy.filters.http.grpc_web", hcm.GetHttpFilters()[0].Name)
	require.Equal(t, "envoy.filters.http.grpc_stats", hcm.GetHttpFilters()[1].Name)
	require.Equal(t, ExtAuthzFilterName(extAuthzFilterKey(authFilters[0])), hcm.GetHttpFilters()[2].Name)
	require.Equal(t, ExtAuthzFilterName(extAuthzFilterKey(authFilters[1])), hcm.GetHttpFilters()[3].Name)
	require.Equal(t, "envoy.filters.http.router", hcm.GetHttpFilters()[4].Name)

	// Verify GRPC filter points to the right cluster
	grpcFilter := &extauthzv3.ExtAuthz{}
	require.NoError(t, proto.Unmarshal(hcm.GetHttpFilters()[2].GetTypedConfig().Value, grpcFilter))
	require.NotNil(t, grpcFilter.GetGrpcService())
	require.Equal(t, "grpc:default:grpc-authz:9000", grpcFilter.GetGrpcService().GetEnvoyGrpc().GetClusterName())

	// Verify HTTP filter has path prefix
	httpFilter := &extauthzv3.ExtAuthz{}
	require.NoError(t, proto.Unmarshal(hcm.GetHttpFilters()[3].GetTypedConfig().Value, httpFilter))
	require.NotNil(t, httpFilter.GetHttpService())
	require.Equal(t, "/auth", httpFilter.GetHttpService().GetPathPrefix())
	require.Equal(t, "http:default:http-authz:8080", httpFilter.GetHttpService().GetServerUri().GetCluster())
}

func Test_buildExtAuthzHTTPFilter_forwardBody(t *testing.T) {
	t.Run("forward body set on GRPC filter", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol:    model.ExternalAuthProtocolGRPC,
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 4096},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetWithRequestBody())
		require.Equal(t, uint32(4096), config.GetWithRequestBody().GetMaxRequestBytes())
		require.True(t, config.GetWithRequestBody().GetAllowPartialMessage())
	})

	t.Run("forward body set on HTTP filter", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:    model.ExternalAuthProtocolHTTP,
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 8192},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetWithRequestBody())
		require.Equal(t, uint32(8192), config.GetWithRequestBody().GetMaxRequestBytes())
		require.True(t, config.GetWithRequestBody().GetAllowPartialMessage())
	})

	t.Run("no forward body when nil", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:  model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol: model.ExternalAuthProtocolHTTP,
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetWithRequestBody())
	})

	t.Run("no forward body when max size is zero", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:    model.ExternalAuthProtocolHTTP,
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 0},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetWithRequestBody())
	})
}

func Test_buildExtAuthzHTTPFilter_allowedRequestHeaders(t *testing.T) {
	// Per the Gateway API spec: if AllowedRequestHeaders is empty, all headers must be sent.
	// We achieve this by leaving AllowedHeaders unset; Envoy then forwards all headers by default.
	t.Run("GRPC empty list forwards all headers (spec: empty means send all)", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol:              model.ExternalAuthProtocolGRPC,
			AllowedRequestHeaders: []string{},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetAllowedHeaders())
	})

	t.Run("GRPC nil list forwards all headers (spec: empty means send all)", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:  model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol: model.ExternalAuthProtocolGRPC,
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetAllowedHeaders())
	})

	t.Run("GRPC explicit headers forwarded", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol:              model.ExternalAuthProtocolGRPC,
			AllowedRequestHeaders: []string{"X-Custom-Header", "X-Tenant-ID"},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetAllowedHeaders())
		require.Len(t, config.GetAllowedHeaders().GetPatterns(), 2)
		require.Equal(t, "X-Custom-Header", config.GetAllowedHeaders().GetPatterns()[0].GetExact())
		require.Equal(t, "X-Tenant-ID", config.GetAllowedHeaders().GetPatterns()[1].GetExact())
	})

	t.Run("HTTP empty list produces no AllowedHeaders (Envoy rejects empty matcher)", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:              model.ExternalAuthProtocolHTTP,
			AllowedRequestHeaders: []string{},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetAllowedHeaders())
	})

	t.Run("HTTP explicit headers forwarded", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:              model.ExternalAuthProtocolHTTP,
			AllowedRequestHeaders: []string{"X-Custom-Header"},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetAllowedHeaders())
		require.Len(t, config.GetAllowedHeaders().GetPatterns(), 1)
		require.Equal(t, "X-Custom-Header", config.GetAllowedHeaders().GetPatterns()[0].GetExact())
	})
}

func Test_getTypedPerFilterConfig(t *testing.T) {
	authFilters := []*model.HTTPExternalAuthFilter{
		{Backend: model.Backend{Name: "svc-a", Namespace: "ns", Port: &model.BackendPort{Port: 9000}}, Protocol: model.ExternalAuthProtocolGRPC},
		{Backend: model.Backend{Name: "svc-b", Namespace: "ns", Port: &model.BackendPort{Port: 8080}}, Protocol: model.ExternalAuthProtocolHTTP},
	}

	t.Run("route without auth disables all filters", func(t *testing.T) {
		cfg := getTypedPerFilterConfig(nil, authFilters, model.HTTPRoute{})
		require.Len(t, cfg, 2)
		for _, v := range cfg {
			perRoute := &extauthzv3.ExtAuthzPerRoute{}
			require.NoError(t, proto.Unmarshal(v.Value, perRoute))
			require.True(t, perRoute.GetDisabled())
		}
	})

	t.Run("route with auth enables its filter and disables others", func(t *testing.T) {
		routeAuth := &model.HTTPExternalAuthFilter{
			Backend:  model.Backend{Name: "svc-a", Namespace: "ns", Port: &model.BackendPort{Port: 9000}},
			Protocol: model.ExternalAuthProtocolGRPC,
		}
		cfg := getTypedPerFilterConfig(routeAuth, authFilters, model.HTTPRoute{})
		// Only svc-b should be disabled; svc-a has no entry (enabled by default)
		require.Len(t, cfg, 1)
		_, hasSvcA := cfg["envoy.filters.http.ext_authz/GRPC:ns:svc-a:9000"]
		require.False(t, hasSvcA, "active auth filter must not be explicitly disabled")
		disabledEntry, hasSvcB := cfg["envoy.filters.http.ext_authz/HTTP:ns:svc-b:8080"]
		require.True(t, hasSvcB)
		perRoute := &extauthzv3.ExtAuthzPerRoute{}
		require.NoError(t, proto.Unmarshal(disabledEntry.Value, perRoute))
		require.True(t, perRoute.GetDisabled())
	})

	t.Run("route with CORS filter", func(t *testing.T) {
		cfg := getTypedPerFilterConfig(nil, nil, model.HTTPRoute{
			CORS: &model.HTTPCORSFilter{MaxAge: 42},
		})
		require.Len(t, cfg, 1)
		cors := &httpCORSv3.CorsPolicy{}
		require.NoError(t, proto.Unmarshal(cfg["envoy.filters.http.cors"].Value, cors))
	})

	t.Run("no auth filters returns nil", func(t *testing.T) {
		require.Nil(t, getTypedPerFilterConfig(nil, nil, model.HTTPRoute{}))
	})
}

func Test_extAuthzFilterKey_sameBackendDifferentConfig(t *testing.T) {
	backend := model.Backend{Name: "authz", Namespace: "ns", Port: &model.BackendPort{Port: 9000}}

	base := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP}
	withPrefix := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, PathPrefix: "/check"}
	withBody := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, ForwardBody: &model.ForwardBodyConfig{MaxSize: 1024}}
	withReqHeaders := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedRequestHeaders: []string{"X-Tenant"}}
	withRespHeaders := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedResponseHeaders: []string{"X-Authz-Status"}}

	keys := []string{
		extAuthzFilterKey(base),
		extAuthzFilterKey(withPrefix),
		extAuthzFilterKey(withBody),
		extAuthzFilterKey(withReqHeaders),
		extAuthzFilterKey(withRespHeaders),
	}
	// All five configs are distinct — each must produce a unique key.
	seen := map[string]struct{}{}
	for _, k := range keys {
		require.NotContains(t, seen, k, "duplicate key: %s", k)
		seen[k] = struct{}{}
	}

	// Identical configs must produce the same key (idempotency).
	require.Equal(t, extAuthzFilterKey(base), extAuthzFilterKey(&model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP}))
	// Header order must not affect the key.
	headersAB := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedRequestHeaders: []string{"A", "B"}}
	headersBA := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedRequestHeaders: []string{"B", "A"}}
	require.Equal(t, extAuthzFilterKey(headersAB), extAuthzFilterKey(headersBA))
}

func Test_desiredHTTPConnectionManagerWithoutGRPCWebTranslation(t *testing.T) {
	i := &cecTranslator{}
	m := &model.Model{
		HTTPOptions: &model.HTTPOptions{
			GRPCWebTranslation: &model.GRPCWebTranslationConfig{
				Enabled: false,
			},
		},
	}
	res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
	require.NoError(t, err)

	httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
	err = proto.Unmarshal(res.Value, httpConnectionManager)
	require.NoError(t, err)

	require.Len(t, httpConnectionManager.GetHttpFilters(), 2)
	require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[0].Name)
	require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[1].Name)
}
