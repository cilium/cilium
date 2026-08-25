// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"log/slog"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/hive/hivetest"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestGammaHTTPRoutesResolvesExtProcService(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	parentService := testService("default", "frontend", 80)
	route := testHTTPRoute([]gatewayv1.HTTPRouteFilter{extProcHTTPFilter("filter-a")})
	route.Spec.ParentRefs = []gatewayv1.ParentReference{{
		Name:  "frontend",
		Group: ptr.To(gatewayv1.Group("")),
		Kind:  ptr.To(gatewayv1.Kind("Service")),
		Port:  ptr.To(gatewayv1.PortNumber(80)),
	}}

	listeners := GammaHTTPRoutes(logger, GammaInput{
		HTTPRoutes:                []gatewayv1.HTTPRoute{route},
		Services:                  []corev1.Service{parentService, testService("default", "backend", 8080), testService("default", "ext-proc", 9001)},
		SourceService:             &parentService,
		EnableExtensionRefFilters: true,
		CiliumEnvoyExtProcFilters: []v2alpha1.CiliumEnvoyExtProcFilter{extProcTestCRD("filter-a", "ext-proc", 9001)},
	})

	require.Len(t, listeners, 1)
	require.Len(t, listeners[0].Routes, 1)
	require.Len(t, listeners[0].Routes[0].ExtensionRefFilters, 1)
	assert.Nil(t, listeners[0].Routes[0].DirectResponse)
}

func TestExtractRoutesAllowsCrossRuleReuseAndSharedBackend(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	filters := []v2alpha1.CiliumEnvoyExtProcFilter{
		extProcTestCRD("filter-a", "ext-proc", 9001),
		extProcTestCRD("filter-b", "ext-proc", 9001),
	}
	services := []corev1.Service{
		testService("default", "backend", 8080),
		testService("default", "ext-proc", 9001),
	}

	route := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{Rules: []gatewayv1.HTTPRouteRule{
			{
				BackendRefs: []gatewayv1.HTTPBackendRef{testHTTPBackendRef()},
				Filters:     []gatewayv1.HTTPRouteFilter{extProcHTTPFilter("filter-a")},
			},
			{
				BackendRefs: []gatewayv1.HTTPBackendRef{testHTTPBackendRef()},
				Filters:     []gatewayv1.HTTPRouteFilter{extProcHTTPFilter("filter-a")},
			},
			{
				BackendRefs: []gatewayv1.HTTPBackendRef{testHTTPBackendRef()},
				Filters: []gatewayv1.HTTPRouteFilter{
					extProcHTTPFilter("filter-a"),
					extProcHTTPFilter("filter-b"),
				},
			},
		}},
	}

	routes := extractRoutes(logger, 80, []string{"*"}, route, services, nil, nil, nil, true, filters)
	require.Len(t, routes, 3)
	for index, route := range routes {
		assert.Nil(t, route.DirectResponse, "route %d should remain valid", index)
	}
	assert.NotNil(t, routes[0].SourceRule, "reused rule identity should be retained")
	assert.NotNil(t, routes[1].SourceRule, "reused rule identity should be retained")
	assert.Len(t, routes[0].ExtensionRefFilters, 1)
	assert.Len(t, routes[1].ExtensionRefFilters, 1)
	assert.Len(t, routes[2].ExtensionRefFilters, 2)
	assert.Equal(t, routes[0].ExtensionRefFilters[0].Backend, routes[2].ExtensionRefFilters[0].Backend)
}

func TestExtractRoutesRejectsMissingExtProcServiceOrPort(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	filter := extProcTestCRD("filter-a", "ext-proc", 9001)
	route := testHTTPRoute([]gatewayv1.HTTPRouteFilter{extProcHTTPFilter("filter-a")})

	tests := map[string][]corev1.Service{
		"missing Service": {
			testService("default", "backend", 8080),
		},
		"missing numeric Service port": {
			testService("default", "backend", 8080),
			testService("default", "ext-proc", 9002),
		},
	}

	for name, services := range tests {
		t.Run(name, func(t *testing.T) {
			routes := extractRoutes(logger, 80, []string{"*"}, route, services, nil, nil, nil, true, []v2alpha1.CiliumEnvoyExtProcFilter{filter})
			require.Len(t, routes, 1)
			require.NotNil(t, routes[0].DirectResponse)
			assert.Equal(t, 500, routes[0].DirectResponse.StatusCode)
			assert.Empty(t, routes[0].ExtensionRefFilters)
			assert.Nil(t, routes[0].SourceRule)
		})
	}
}

func extProcTestCRD(name, service string, port int32) v2alpha1.CiliumEnvoyExtProcFilter {
	return v2alpha1.CiliumEnvoyExtProcFilter{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
			BackendRef: v2alpha1.ExtProcBackendRef{Name: service, Port: port},
		},
	}
}

func extProcHTTPFilter(name string) gatewayv1.HTTPRouteFilter {
	return gatewayv1.HTTPRouteFilter{
		Type:         gatewayv1.HTTPRouteFilterExtensionRef,
		ExtensionRef: &gatewayv1.LocalObjectReference{Group: "cilium.io", Kind: "CiliumEnvoyExtProcFilter", Name: gatewayv1.ObjectName(name)},
	}
}

func testHTTPBackendRef() gatewayv1.HTTPBackendRef {
	return gatewayv1.HTTPBackendRef{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{
		Name: "backend",
		Port: ptr.To(gatewayv1.PortNumber(8080)),
	}}}
}

func testHTTPRoute(filters []gatewayv1.HTTPRouteFilter) gatewayv1.HTTPRoute {
	return gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{Rules: []gatewayv1.HTTPRouteRule{{
			BackendRefs: []gatewayv1.HTTPBackendRef{testHTTPBackendRef()},
			Filters:     filters,
		}}},
	}
}
