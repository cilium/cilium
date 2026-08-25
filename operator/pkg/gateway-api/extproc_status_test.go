// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/loading"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/operator/pkg/model"

	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestPersistGatewayRouteStatusesPreservesSnapshotResourceVersion(t *testing.T) {
	original := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default", ResourceVersion: "1"},
		Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
			Conditions: []metav1.Condition{{Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionTrue}},
		}}}},
	}
	desired := *original.DeepCopy()
	desired.Status.Parents[0].Conditions[0].Reason = "OrderingConflict"

	var update client.Object
	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		WithObjects(&original).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, subresource string, obj client.Object, _ ...client.SubResourceUpdateOption) error {
				require.Equal(t, "status", subresource)
				update = obj
				return apierrors.NewConflict(schema.GroupResource{Group: gatewayv1.GroupName, Resource: "httproutes"}, original.Name, nil)
			},
		}).
		Build()

	m := &RouteStatusManager{client: c}
	err := m.persistGatewayRouteStatuses(t.Context(), slog.Default(), []gatewayv1.HTTPRoute{original}, []gatewayv1.HTTPRoute{desired}, nil, nil)
	require.Error(t, err)
	require.NotNil(t, update)
	require.Equal(t, "1", update.GetResourceVersion())
}

func TestSetRouteStatusesReturnsComputedViewsWithoutWriting(t *testing.T) {
	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "class"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(defaultControllerName),
		},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "class",
			Listeners: []gatewayv1.Listener{{
				Name:     "http",
				Port:     80,
				Protocol: gatewayv1.HTTPProtocolType,
			}},
		},
	}
	httpRoute := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "http-route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{
			ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}},
		}},
	}
	grpcRoute := gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "grpc-route", Namespace: "default"},
		Spec: gatewayv1.GRPCRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{
			ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}},
		}},
	}

	statusUpdates := 0
	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithObjects(gatewayClass, gateway).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}, &gatewayv1.GRPCRoute{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, subresource string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				if subresource == "status" {
					statusUpdates++
				}
				return nil
			},
		}).
		Build()

	manager := NewRouteStatusManager(c, slog.Default(), defaultControllerName, RouteStatusManagerConfig{})
	httpInput := []gatewayv1.HTTPRoute{httpRoute}
	grpcInput := []gatewayv1.GRPCRoute{grpcRoute}
	result, err := manager.SetRouteStatuses(t.Context(), slog.Default(), RouteStatusInputs{
		HTTPRoutes: httpInput,
		GRPCRoutes: grpcInput,
	})
	require.NoError(t, err)
	require.Len(t, result.HTTPRoutes[0].Status.Parents, 1)
	require.Len(t, result.GRPCRoutes[0].Status.Parents, 1)
	require.Empty(t, httpInput[0].Status.Parents)
	require.Empty(t, grpcInput[0].Status.Parents)
	require.Zero(t, statusUpdates)
}

func TestOverlayExtProcOrderingConflicts(t *testing.T) {
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	parentRef := extProcGatewayParent("gateway", "http", 80)

	modelRoute := func(name string, creation time.Time) model.HTTPRoute {
		return model.HTTPRoute{ExtensionRefFilters: []model.ExtensionRefFilter{
			extProcStatusFilter("alpha", name, creation, 0),
			extProcStatusFilter("beta", name, creation, 1),
		}}
	}
	modelRouteNewer := model.HTTPRoute{ExtensionRefFilters: []model.ExtensionRefFilter{
		extProcStatusFilter("beta", "new", newer, 0),
		extProcStatusFilter("alpha", "new", newer, 1),
	}}

	routes := []gatewayv1.HTTPRoute{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: "default", UID: "old-uid", Generation: 1},
			Status:     gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{extProcStatusParent(parentRef, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted)}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "new", Namespace: "default", UID: "new-uid", Generation: 1},
			Status:     gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{extProcStatusParent(parentRef, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted)}}},
		},
	}
	m := &model.Model{HTTP: []model.HTTPListener{{
		Name:    "http",
		Port:    80,
		Sources: []model.FullyQualifiedResource{{Name: "gateway", Namespace: "default", Kind: "Gateway"}},
		Routes:  []model.HTTPRoute{modelRoute("old", old), modelRouteNewer},
	}}}

	(&gatewayReconciler{}).overlayExtProcOrderingConflictsInMemory(m, routes, nil)

	oldCondition := routes[0].Status.Parents[0].Conditions[0]
	require.Equal(t, metav1.ConditionTrue, oldCondition.Status)
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), oldCondition.Reason)
	newCondition := routes[1].Status.Parents[0].Conditions[0]
	require.Equal(t, metav1.ConditionFalse, newCondition.Status)
	require.Equal(t, "OrderingConflict", newCondition.Reason)
	require.True(t, strings.HasPrefix(newCondition.Message, "Rejected Rule:"))
	require.Contains(t, newCondition.Message, routeOrderingConflictMessage)

	require.Nil(t, m.HTTP[0].Routes[0].DirectResponse)
	require.Len(t, m.HTTP[0].Routes[0].ExtensionRefFilters, 2)
	require.NotNil(t, m.HTTP[0].Routes[1].DirectResponse)
	require.Equal(t, 500, m.HTTP[0].Routes[1].DirectResponse.StatusCode)
	require.Nil(t, m.HTTP[0].Routes[1].Backends)
	require.Nil(t, m.HTTP[0].Routes[1].ExternalAuth)
	require.Empty(t, m.HTTP[0].Routes[1].ExtensionRefFilters)
}

func TestOverlayExtProcOrderingConflictPreservesValidSiblingRule(t *testing.T) {
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	parentRef := extProcGatewayParent("gateway", "http", 80)
	parent := model.FullyQualifiedResource{Name: "gateway", Namespace: "default", Kind: "Gateway"}
	peerSource := model.FullyQualifiedResource{Name: "peer", Namespace: "default", Kind: "HTTPRoute", UID: "peer-uid"}
	targetSource := model.FullyQualifiedResource{Name: "target", Namespace: "default", Kind: "HTTPRoute", UID: "target-uid"}
	validRule := &model.HTTPRouteRule{Source: targetSource, RuleIndex: 0}
	invalidRule := &model.HTTPRouteRule{Source: targetSource, RuleIndex: 1}

	m := &model.Model{HTTP: []model.HTTPListener{{
		Name: "http", Port: 80, Sources: []model.FullyQualifiedResource{parent},
		Routes: []model.HTTPRoute{
			{SourceRoute: &peerSource, SourceRule: &model.HTTPRouteRule{Source: peerSource, RuleIndex: 0}, ExtensionRefFilters: []model.ExtensionRefFilter{
				extProcStatusFilterWithRule("alpha", peerSource, old, 0),
				extProcStatusFilterWithRule("beta", peerSource, old, 0),
			}},
			{SourceRoute: &targetSource, SourceRule: validRule},
			{SourceRoute: &targetSource, SourceRule: invalidRule, ExtensionRefFilters: []model.ExtensionRefFilter{
				extProcStatusFilterWithRule("beta", targetSource, newer, 1),
				extProcStatusFilterWithRule("alpha", targetSource, newer, 1),
			}},
		},
	}}}
	routes := []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default", UID: "target-uid", Generation: 1},
		Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{
			extProcStatusParent(parentRef, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted),
		}}},
	}}

	(&gatewayReconciler{}).overlayExtProcOrderingConflictsInMemory(m, routes, nil)

	accepted := findRouteAcceptedCondition(routes[0].Status.Parents[0].Conditions)
	require.NotNil(t, accepted)
	require.Equal(t, metav1.ConditionTrue, accepted.Status)
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), accepted.Reason)
	partial := findRouteCondition(routes[0].Status.Parents[0].Conditions, gatewayv1.RouteConditionPartiallyInvalid)
	require.NotNil(t, partial)
	require.Equal(t, metav1.ConditionTrue, partial.Status)
	require.Equal(t, string(routeReasonOrderingConflict), partial.Reason)
	require.True(t, strings.HasPrefix(partial.Message, "Dropped Rule"))
	require.Nil(t, m.HTTP[0].Routes[1].DirectResponse)
	require.NotNil(t, m.HTTP[0].Routes[2].DirectResponse)
	require.Equal(t, 500, m.HTTP[0].Routes[2].DirectResponse.StatusCode)
}

func TestOverlayExtProcStaticInvalidityPreservesValidSiblingRule(t *testing.T) {
	parentRef := extProcGatewayParent("gateway", "http", 80)
	parent := model.FullyQualifiedResource{Name: "gateway", Namespace: "default", Kind: "Gateway"}

	tests := []struct {
		name           string
		routeKind      string
		invalidMessage string
	}{
		{name: "HTTPRoute declaration order", routeKind: "HTTPRoute", invalidMessage: "declares ext_proc filter \"filter-a\" after ExternalAuth"},
		{name: "HTTPRoute duplicate", routeKind: "HTTPRoute", invalidMessage: "references ext_proc filter \"filter-a\" more than once"},
		{name: "GRPCRoute duplicate", routeKind: "GRPCRoute", invalidMessage: "references ext_proc filter \"filter-a\" more than once"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := model.FullyQualifiedResource{Name: "target", Namespace: "default", Kind: tt.routeKind, UID: "target-uid"}
			validRule := &model.HTTPRouteRule{Source: source, RuleIndex: 0}
			invalidRule := &model.HTTPRouteRule{Source: source, RuleIndex: 1}
			m := &model.Model{HTTP: []model.HTTPListener{{
				Name: "http", Port: 80, Sources: []model.FullyQualifiedResource{parent},
				Routes: []model.HTTPRoute{
					{SourceRoute: &source, SourceRule: validRule},
					{SourceRoute: &source, SourceRule: invalidRule, ExtProcInvalidReason: model.ExtProcRouteInvalidDuplicate, ExtProcInvalidMessage: tt.invalidMessage},
				},
			}}}

			statusParent := extProcStatusParent(parentRef, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted)
			var conditions []metav1.Condition
			if tt.routeKind == "HTTPRoute" {
				routes := []gatewayv1.HTTPRoute{{
					ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default", UID: "target-uid", Generation: 1},
					Status:     gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{statusParent}}},
				}}
				(&gatewayReconciler{}).overlayExtProcOrderingConflictsInMemory(m, routes, nil)
				conditions = routes[0].Status.Parents[0].Conditions
			} else {
				routes := []gatewayv1.GRPCRoute{{
					ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default", UID: "target-uid", Generation: 1},
					Status:     gatewayv1.GRPCRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{statusParent}}},
				}}
				(&gatewayReconciler{}).overlayExtProcOrderingConflictsInMemory(m, nil, routes)
				conditions = routes[0].Status.Parents[0].Conditions
			}

			accepted := findRouteAcceptedCondition(conditions)
			require.NotNil(t, accepted)
			require.Equal(t, metav1.ConditionTrue, accepted.Status)
			require.Equal(t, string(gatewayv1.RouteReasonAccepted), accepted.Reason)
			partial := findRouteCondition(conditions, gatewayv1.RouteConditionPartiallyInvalid)
			require.NotNil(t, partial)
			require.Equal(t, string(gatewayv1.RouteReasonIncompatibleFilters), partial.Reason)
			require.Equal(t, "Dropped Rule: "+helpers.ExtProcConditionMessagePrefix+"rule 1: "+tt.invalidMessage, partial.Message)
			require.Nil(t, m.HTTP[0].Routes[0].DirectResponse)
			require.NotNil(t, m.HTTP[0].Routes[1].DirectResponse)
			require.Equal(t, 500, m.HTTP[0].Routes[1].DirectResponse.StatusCode)
		})
	}
}

func TestClearExtProcPartiallyInvalidConditionsScopesOwnership(t *testing.T) {
	ciliumController := gatewayv1.GatewayController(defaultControllerName)
	otherController := gatewayv1.GatewayController("example.com/other")
	extProcPartial := metav1.Condition{
		Type: string(gatewayv1.RouteConditionPartiallyInvalid), Status: metav1.ConditionTrue,
		Reason:  string(gatewayv1.RouteReasonIncompatibleFilters),
		Message: "Dropped Rule: " + helpers.ExtProcConditionMessagePrefix + "rule 1: invalid",
	}
	unrelatedPartial := metav1.Condition{
		Type: string(gatewayv1.RouteConditionPartiallyInvalid), Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.RouteReasonIncompatibleFilters), Message: "Dropped Rule: unrelated",
	}
	parents := []gatewayv1.RouteParentStatus{
		{ControllerName: ciliumController, Conditions: []metav1.Condition{extProcPartial, unrelatedPartial}},
		{ControllerName: otherController, Conditions: []metav1.Condition{extProcPartial}},
	}

	clearExtProcPartiallyInvalidConditions(parents, defaultControllerName)

	require.Equal(t, []metav1.Condition{unrelatedPartial}, parents[0].Conditions)
	require.Equal(t, []metav1.Condition{extProcPartial}, parents[1].Conditions)
}

func TestPreserveExtProcConditionsIgnoresUnrelatedIncompatibleFilters(t *testing.T) {
	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway-a", Namespace: "default"}}
	otherParent := extProcGatewayParent("gateway-b", "http", 80)
	controller := gatewayv1.GatewayController(defaultControllerName)
	original := gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
		ParentRef: otherParent, ControllerName: controller,
		Conditions: []metav1.Condition{{
			Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.RouteReasonIncompatibleFilters), Message: "unrelated filter conflict",
		}},
	}}}
	desired := gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
		ParentRef: otherParent, ControllerName: controller,
		Conditions: []metav1.Condition{{
			Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionTrue,
			Reason: string(gatewayv1.RouteReasonAccepted),
		}},
	}}}

	r := &gatewayReconciler{controllerName: defaultControllerName}
	r.preserveExtProcOrderingConflictsOutsideGatewayForRoute(gateway, nil, "default", &original, &desired)

	require.Equal(t, metav1.ConditionTrue, desired.Parents[0].Conditions[0].Status)
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), desired.Parents[0].Conditions[0].Reason)
}

func TestOverlayExtProcOrderingConflictRequiresAcceptedParent(t *testing.T) {
	creation := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	parentRef := extProcGatewayParent("gateway", "http", 80)
	m := &model.Model{HTTP: []model.HTTPListener{{
		Name:    "http",
		Port:    80,
		Sources: []model.FullyQualifiedResource{{Name: "gateway", Namespace: "default", Kind: "Gateway"}},
		Routes: []model.HTTPRoute{
			{ExtensionRefFilters: []model.ExtensionRefFilter{
				extProcStatusFilter("alpha", "old", creation, 0),
				extProcStatusFilter("beta", "old", creation, 1),
			}},
			{ExtensionRefFilters: []model.ExtensionRefFilter{
				extProcStatusFilter("beta", "new", creation.Add(time.Hour), 0),
				extProcStatusFilter("alpha", "new", creation.Add(time.Hour), 1),
			}},
		},
	}}}

	for _, status := range []metav1.ConditionStatus{metav1.ConditionFalse, metav1.ConditionUnknown} {
		route := gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "new", Namespace: "default", UID: "new-uid", Generation: 1},
			Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{
				extProcStatusParent(parentRef, status, gatewayv1.RouteReasonAccepted),
			}}},
		}
		routes := []gatewayv1.HTTPRoute{route}
		(&gatewayReconciler{}).overlayExtProcOrderingConflictsInMemory(m, routes, nil)
		condition := routes[0].Status.Parents[0].Conditions[0]
		require.Equal(t, status, condition.Status)
		require.NotEqual(t, "OrderingConflict", condition.Reason)
		require.NotNil(t, m.HTTP[0].Routes[1].DirectResponse)
		require.Equal(t, 500, m.HTTP[0].Routes[1].DirectResponse.StatusCode)
	}
}

func TestOrderingConflictIsClearedByAcceptedStatusReconciliation(t *testing.T) {
	parentRef := extProcGatewayParent("gateway", "http", 80)
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default", Generation: 1},
		Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{
			extProcStatusParent(parentRef, metav1.ConditionTrue, routeReasonOrderingConflict),
		}}},
	}
	input := &routechecks.HTTPRouteInput{HTTPRoute: route}
	input.SetParentCondition(parentRef, metav1.Condition{
		Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.RouteReasonAccepted), Message: "Accepted HTTPRoute",
	})

	condition := route.Status.Parents[0].Conditions[0]
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), condition.Reason)
	require.NotEqual(t, string(routeReasonOrderingConflict), condition.Reason)
}

func TestAlternatingReconciliationScopesExtProcOrderingConflict(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	parentA := extProcGatewayParent("gateway-a", "http", 80)
	parentB := extProcGatewayParent("gateway-b", "http", 80)
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	peer := extProcOrderingHTTPRoute("peer", "peer-uid", old, []gatewayv1.ParentReference{parentA}, "alpha", "beta")
	target := extProcOrderingHTTPRoute("target", "target-uid", newer, []gatewayv1.ParentReference{parentA, parentB}, "beta", "alpha")
	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController(defaultControllerName)},
	}
	gatewayA := extProcOrderingGateway("gateway-a")
	gatewayB := extProcOrderingGateway("gateway-b")
	extProcService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "ext-proc", Namespace: "default"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.0.0.10", Ports: []corev1.ServicePort{{Name: "grpc", Port: 9000}}},
	}
	backendService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "default"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.0.0.11", Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}},
	}
	filters := []client.Object{
		&v2alpha1.CiliumEnvoyExtProcFilter{ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "default"}, Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{BackendRef: v2alpha1.ExtProcBackendRef{Name: "ext-proc", Port: 9000}}},
		&v2alpha1.CiliumEnvoyExtProcFilter{ObjectMeta: metav1.ObjectMeta{Name: "beta", Namespace: "default"}, Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{BackendRef: v2alpha1.ExtProcBackendRef{Name: "ext-proc", Port: 9000}}},
	}

	scheme := helpers.TestScheme(helpers.AllOptionalKinds)
	clientBuilder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gatewayClass, gatewayA, gatewayB, peer, target, extProcService, backendService).
		WithStatusSubresource(&gatewayv1.Gateway{}, &gatewayv1.GatewayClass{}, &gatewayv1.HTTPRoute{}).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.GatewayHTTPRouteIndex, indexers.IndexHTTPRouteByGateway).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.GatewayGRPCRouteIndex, indexers.IndexGRPCRouteByGateway).
		WithIndex(&gatewayv1.TLSRoute{}, indexers.GatewayTLSRouteIndex, indexers.IndexTLSRouteByGateway)
	for _, filter := range filters {
		clientBuilder = clientBuilder.WithObjects(filter)
	}
	c := clientBuilder.Build()

	cecTranslator := translation.NewCECTranslator(translation.Config{
		SecretsNamespace: "cilium-secrets",
		RouteConfig:      translation.RouteConfig{HostNameSuffixMatch: true},
		ListenerConfig:   translation.ListenerConfig{StreamIdleTimeoutSeconds: 300},
		ClusterConfig:    translation.ClusterConfig{IdleTimeoutSeconds: 60},
	})
	translator := gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{
		ServiceConfig:             translation.ServiceConfig{ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster)},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{UseRemoteAddress: true},
	})
	r := &gatewayReconciler{
		client: c, scheme: scheme, translator: translator,
		inputLoader:           loading.NewTranslationInputLoader(c, logger, defaultControllerName, loading.TranslationInputLoaderConfig{IncludeExtProcFilters: true}),
		listenerStatusManager: NewListenerStatusManager(c, logger, ListenerStatusManagerConfig{TCPUDPRouteSupport: true}),
		routeStatusManager: NewRouteStatusManager(c, logger, defaultControllerName, RouteStatusManagerConfig{
			ExtensionRefFiltersEnabled: true,
		}),
		backendTLSPolicyStatusManager: NewBackendTLSPolicyStatusManager(c, defaultControllerName),
		gatewayAddressStatusManager:   NewGatewayAddressStatusManager(c, logger),
		logger:                        logger, controllerName: defaultControllerName, enableExtensionRefFilters: true,
	}
	reconcile := func(gatewayName string) {
		_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Name: gatewayName, Namespace: "default"}})
		require.NoError(t, err)
	}
	getTarget := func() gatewayv1.HTTPRoute {
		var current gatewayv1.HTTPRoute
		require.NoError(t, c.Get(t.Context(), types.NamespacedName{Name: "target", Namespace: "default"}, &current))
		return current
	}
	conditionFor := func(route gatewayv1.HTTPRoute, parent gatewayv1.ParentReference) metav1.Condition {
		for _, status := range route.Status.Parents {
			if status.ParentRef.Name == parent.Name {
				condition := findRouteAcceptedCondition(status.Conditions)
				require.NotNil(t, condition)
				return *condition
			}
		}
		t.Fatalf("parent %q missing from Route status", parent.Name)
		return metav1.Condition{}
	}
	reasonFor := func(route gatewayv1.HTTPRoute, parent gatewayv1.ParentReference) string {
		return conditionFor(route, parent).Reason
	}

	// The newer target loses its reverse ordering constraint to the older peer
	// in Gateway A's aggregate, while Gateway B sees only the target.
	reconcile("gateway-a")
	targetStatus := getTarget()
	require.Equal(t, metav1.ConditionFalse, conditionFor(targetStatus, parentA).Status)
	require.Equal(t, string(routeReasonOrderingConflict), reasonFor(targetStatus, parentA))
	require.Equal(t, metav1.ConditionTrue, conditionFor(targetStatus, parentB).Status)
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), reasonFor(targetStatus, parentB))
	requireCECHasDirectResponse(t, c, "gateway-a", true)

	reconcile("gateway-b")
	targetStatus = getTarget()
	require.Equal(t, metav1.ConditionFalse, conditionFor(targetStatus, parentA).Status)
	require.Equal(t, string(routeReasonOrderingConflict), reasonFor(targetStatus, parentA))
	require.Equal(t, metav1.ConditionTrue, conditionFor(targetStatus, parentB).Status)
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), reasonFor(targetStatus, parentB))
	requireCECHasDirectResponse(t, c, "gateway-b", false)

	reconcile("gateway-a")
	targetStatus = getTarget()
	require.Equal(t, metav1.ConditionFalse, conditionFor(targetStatus, parentA).Status)
	require.Equal(t, string(routeReasonOrderingConflict), reasonFor(targetStatus, parentA))
	require.Equal(t, metav1.ConditionTrue, conditionFor(targetStatus, parentB).Status)
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), reasonFor(targetStatus, parentB))
	requireCECHasDirectResponse(t, c, "gateway-a", true)

	require.NoError(t, c.Delete(t.Context(), peer))
	reconcile("gateway-a")
	targetStatus = getTarget()
	require.Equal(t, metav1.ConditionTrue, conditionFor(targetStatus, parentA).Status)
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), reasonFor(targetStatus, parentA))
	require.Equal(t, metav1.ConditionTrue, conditionFor(targetStatus, parentB).Status)
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), reasonFor(targetStatus, parentB))
	requireCECHasDirectResponse(t, c, "gateway-a", false)
}

func requireCECHasDirectResponse(t *testing.T, c client.Client, gatewayName string, want bool) {
	t.Helper()

	cec := &ciliumv2.CiliumEnvoyConfig{}
	require.NoError(t, c.Get(t.Context(), types.NamespacedName{
		Namespace: "default",
		Name:      gatewayApiTranslation.CiliumGatewayPrefix + gatewayName,
	}, cec))

	found := false
	for _, resource := range cec.Spec.Resources {
		if resource.Any == nil || resource.TypeUrl != "type.googleapis.com/envoy.config.route.v3.RouteConfiguration" {
			continue
		}

		routeConfig := &envoy_config_route_v3.RouteConfiguration{}
		require.NoError(t, proto.Unmarshal(resource.Value, routeConfig))
		for _, virtualHost := range routeConfig.VirtualHosts {
			for _, route := range virtualHost.Routes {
				if route.GetDirectResponse() != nil && route.GetDirectResponse().Status == 500 {
					found = true
				}
			}
		}
	}

	require.Equal(t, want, found)
}

func extProcOrderingGateway(name string) *gatewayv1.Gateway {
	return &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}, Spec: gatewayv1.GatewaySpec{GatewayClassName: "cilium", Listeners: []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}}}}
}

func extProcOrderingHTTPRoute(name, uid string, creation time.Time, parents []gatewayv1.ParentReference, first, second string) *gatewayv1.HTTPRoute {
	extensionRef := func(filterName string) gatewayv1.HTTPRouteFilter {
		return gatewayv1.HTTPRouteFilter{Type: gatewayv1.HTTPRouteFilterExtensionRef, ExtensionRef: &gatewayv1.LocalObjectReference{Group: "cilium.io", Kind: "CiliumEnvoyExtProcFilter", Name: gatewayv1.ObjectName(filterName)}}
	}
	return &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", UID: types.UID(uid), CreationTimestamp: metav1.NewTime(creation), Generation: 1}, Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parents}, Rules: []gatewayv1.HTTPRouteRule{{Filters: []gatewayv1.HTTPRouteFilter{extensionRef(first), extensionRef(second)}, BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend", Port: ptr.To(gatewayv1.PortNumber(8080))}}}}}}}}
}

func TestListenerSetRouteChecksValidateExtensionRefs(t *testing.T) {
	// A ListenerSet ParentRef must reach CheckExtensionRefs through
	// RouteStatusManager.runListenerSetRouteChecks: the manager has to resolve the
	// ListenerSet, then its parent Gateway, then confirm the controller matches
	// before any backend check runs. Calling CheckExtensionRefs directly would
	// prove none of that.
	logger := hivetest.Logger(t)
	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController(defaultControllerName)},
	}
	gateway := extProcOrderingGateway("gateway")
	listenerSet := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Name: "my-listenerset", Namespace: "default"},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: gatewayv1.ObjectName(gateway.Name)},
			Listeners: []gatewayv1.ListenerEntry{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
		},
	}
	backendService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "default"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.0.0.11", Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}},
	}
	route := extProcOrderingHTTPRoute("route", "route-uid", time.Time{},
		[]gatewayv1.ParentReference{extProcParent("ListenerSet", "my-listenerset", "http", 80)}, "missing", "missing")

	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithObjects(gatewayClass, gateway, listenerSet, backendService, route).
		Build()
	m := NewRouteStatusManager(c, logger, defaultControllerName, RouteStatusManagerConfig{ExtensionRefFiltersEnabled: true})

	result, err := m.SetRouteStatuses(t.Context(), logger, RouteStatusInputs{HTTPRoutes: []gatewayv1.HTTPRoute{*route}})
	require.NoError(t, err)
	require.Len(t, result.HTTPRoutes, 1)
	require.Len(t, result.HTTPRoutes[0].Status.Parents, 1)

	parentStatus := result.HTTPRoutes[0].Status.Parents[0]
	require.Equal(t, gatewayv1.ObjectName("my-listenerset"), parentStatus.ParentRef.Name)
	require.Equal(t, gatewayv1.Kind("ListenerSet"), *parentStatus.ParentRef.Kind)

	var resolvedRefs *metav1.Condition
	for i, condition := range parentStatus.Conditions {
		if condition.Type == string(gatewayv1.RouteConditionResolvedRefs) {
			resolvedRefs = &parentStatus.Conditions[i]
		}
	}
	require.NotNil(t, resolvedRefs, "ListenerSet parent has no ResolvedRefs condition")
	require.Equal(t, metav1.ConditionFalse, resolvedRefs.Status)
	require.Equal(t, string(gatewayv1.RouteReasonBackendNotFound), resolvedRefs.Reason)
}

func TestOverlayExtProcOrderingConflictScopesGatewayParents(t *testing.T) {
	// The conflicting GRPCRoute attaches to both a ListenerSet and a Gateway, but
	// only the ListenerSet listener carries the conflicting aggregate.
	creation := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	gatewayParent := extProcGatewayParent("gateway", "http", 80)
	listenerSetParent := extProcParent("ListenerSet", "listenerset", "http", 80)

	m := &model.Model{HTTP: []model.HTTPListener{{
		Name:    "http",
		Port:    80,
		Sources: []model.FullyQualifiedResource{{Name: "listenerset", Namespace: "default", Kind: "ListenerSet"}},
		Routes: []model.HTTPRoute{
			{ExtensionRefFilters: []model.ExtensionRefFilter{
				extProcStatusFilterKind("alpha", "old-http", "HTTPRoute", creation, 0),
				extProcStatusFilterKind("beta", "old-http", "HTTPRoute", creation, 1),
			}},
			{ExtensionRefFilters: []model.ExtensionRefFilter{
				extProcStatusFilterKind("beta", "new-grpc", "GRPCRoute", creation.Add(time.Hour), 0),
				extProcStatusFilterKind("alpha", "new-grpc", "GRPCRoute", creation.Add(time.Hour), 1),
			}},
		},
	}}}

	grpcRoutes := []gatewayv1.GRPCRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "new-grpc", Namespace: "default", UID: "new-grpc-uid", Generation: 1},
		Status: gatewayv1.GRPCRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{
			extProcStatusParent(listenerSetParent, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted),
			extProcStatusParent(gatewayParent, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted),
		}}},
	}}

	(&gatewayReconciler{}).overlayExtProcOrderingConflictsInMemory(m, nil, grpcRoutes)

	conditions := grpcRoutes[0].Status.Parents
	require.Len(t, conditions, 2)
	require.Equal(t, listenerSetParent.Name, conditions[0].ParentRef.Name)
	require.Equal(t, metav1.ConditionFalse, conditions[0].Conditions[0].Status)
	require.Equal(t, string(routeReasonOrderingConflict), conditions[0].Conditions[0].Reason)
	require.Equal(t, gatewayParent.Name, conditions[1].ParentRef.Name)
	require.Equal(t, metav1.ConditionTrue, conditions[1].Conditions[0].Status)
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), conditions[1].Conditions[0].Reason)
	require.NotNil(t, m.HTTP[0].Routes[1].DirectResponse)
	require.Equal(t, 500, m.HTTP[0].Routes[1].DirectResponse.StatusCode)
	require.Nil(t, m.HTTP[0].Routes[1].Backends)
	require.Nil(t, m.HTTP[0].Routes[1].ExternalAuth)
	require.Empty(t, m.HTTP[0].Routes[1].ExtensionRefFilters)
}

func TestOverlayExtProcOrderingConflictScopesGammaServiceParents(t *testing.T) {
	// The conflicting HTTPRoute attaches to two GAMMA Services, but only the
	// reconciled Service contributes the conflicting aggregate.
	creation := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	serviceParent := extProcStatusServiceParent("service-a", 80)
	otherServiceParent := extProcStatusServiceParent("service-b", 80)

	gammaModel := &model.Model{HTTP: []model.HTTPListener{{
		Name:    "service-a",
		Port:    80,
		Sources: []model.FullyQualifiedResource{{Name: "service-a", Namespace: "default", Kind: "Service"}},
		Routes: []model.HTTPRoute{{ExtensionRefFilters: []model.ExtensionRefFilter{
			extProcStatusFilterKind("alpha", "old-http", "HTTPRoute", creation, 0),
			extProcStatusFilterKind("beta", "old-http", "HTTPRoute", creation, 1),
		}}, {ExtensionRefFilters: []model.ExtensionRefFilter{
			extProcStatusFilterKind("beta", "new-http", "HTTPRoute", creation.Add(time.Hour), 0),
			extProcStatusFilterKind("alpha", "new-http", "HTTPRoute", creation.Add(time.Hour), 1),
		}}},
	}}}
	httpRoutes := &gatewayv1.HTTPRouteList{Items: []gatewayv1.HTTPRoute{{
		ObjectMeta: metav1.ObjectMeta{Name: "new-http", Namespace: "default", UID: "new-http-uid", Generation: 1},
		Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{
			extProcStatusParent(serviceParent, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted),
			extProcStatusParent(otherServiceParent, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted),
		}}},
	}}}

	(&gammaReconciler{}).overlayExtProcOrderingConflictsInMemory(gammaModel, httpRoutes, &gatewayv1.GRPCRouteList{})

	conditions := httpRoutes.Items[0].Status.Parents
	require.Len(t, conditions, 2)
	require.Equal(t, serviceParent.Name, conditions[0].ParentRef.Name)
	require.Equal(t, metav1.ConditionFalse, conditions[0].Conditions[0].Status)
	require.Equal(t, string(routeReasonOrderingConflict), conditions[0].Conditions[0].Reason)
	require.Equal(t, otherServiceParent.Name, conditions[1].ParentRef.Name)
	require.Equal(t, metav1.ConditionTrue, conditions[1].Conditions[0].Status)
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), conditions[1].Conditions[0].Reason)
	require.NotNil(t, gammaModel.HTTP[0].Routes[1].DirectResponse)
	require.Equal(t, 500, gammaModel.HTTP[0].Routes[1].DirectResponse.StatusCode)
	require.Nil(t, gammaModel.HTTP[0].Routes[1].Backends)
	require.Nil(t, gammaModel.HTTP[0].Routes[1].ExternalAuth)
	require.Empty(t, gammaModel.HTTP[0].Routes[1].ExtensionRefFilters)
}

func extProcStatusFilterWithRule(name string, source model.FullyQualifiedResource, creation time.Time, ruleIndex int) model.ExtensionRefFilter {
	return model.ExtensionRefFilter{
		Name:                         name,
		SourceRouteCreationTimestamp: creation,
		SourceRouteRule:              &model.HTTPRouteRule{Source: source, RuleIndex: ruleIndex},
	}
}

func extProcStatusFilter(name, routeName string, creation time.Time, filterIndex int) model.ExtensionRefFilter {
	return extProcStatusFilterKind(name, routeName, "HTTPRoute", creation, filterIndex)
}

func extProcStatusFilterKind(name, routeName, kind string, creation time.Time, filterIndex int) model.ExtensionRefFilter {
	return model.ExtensionRefFilter{
		Name:                         name,
		SourceRouteCreationTimestamp: creation,
		SourceRouteRule: &model.HTTPRouteRule{Source: model.FullyQualifiedResource{
			Name: routeName, Namespace: "default", Kind: kind, UID: routeName + "-uid",
		}},
	}
}

func findRouteCondition(conditions []metav1.Condition, conditionType gatewayv1.RouteConditionType) *metav1.Condition {
	for index := range conditions {
		if conditions[index].Type == string(conditionType) {
			return &conditions[index]
		}
	}
	return nil
}

func extProcStatusParent(parent gatewayv1.ParentReference, status metav1.ConditionStatus, reason gatewayv1.RouteConditionReason) gatewayv1.RouteParentStatus {
	return gatewayv1.RouteParentStatus{
		ParentRef: parent,
		Conditions: []metav1.Condition{{
			Type: string(gatewayv1.RouteConditionAccepted), Status: status, Reason: string(reason),
		}},
	}
}

func extProcGatewayParent(name, section string, port gatewayv1.PortNumber) gatewayv1.ParentReference {
	return extProcParent("Gateway", name, section, port)
}

func extProcParent(kind, name, section string, port gatewayv1.PortNumber) gatewayv1.ParentReference {
	return gatewayv1.ParentReference{
		Group:       ptr.To(gatewayv1.Group(gatewayv1.GroupName)),
		Kind:        ptr.To(gatewayv1.Kind(kind)),
		Name:        gatewayv1.ObjectName(name),
		SectionName: ptr.To(gatewayv1.SectionName(section)),
		Port:        ptr.To(port),
	}
}

func extProcStatusServiceParent(name string, port gatewayv1.PortNumber) gatewayv1.ParentReference {
	return gatewayv1.ParentReference{
		Group: ptr.To(gatewayv1.Group("")),
		Kind:  ptr.To(gatewayv1.Kind("Service")),
		Name:  gatewayv1.ObjectName(name),
		Port:  ptr.To(port),
	}
}
