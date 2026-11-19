// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
)

func TestPruneRouteParentStatuses(t *testing.T) {
	// currentParentSpec and currentParentStatus have identical values but distinct
	// pointer instances, simulating spec vs status after an APIServer round-trip.
	currentParentSpec := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: ptr.To[gatewayv1.Namespace]("default"),
		Name:      "current-gateway",
	}
	currentParentStatus := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: ptr.To[gatewayv1.Namespace]("default"),
		Name:      "current-gateway",
	}
	ourDetachedParent := gatewayv1.ParentReference{
		Name: "detached-gateway",
	}
	otherControllerDetachedParent := gatewayv1.ParentReference{
		Name: "other-controller-gateway",
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "route",
			Namespace:  "default",
			Generation: 7,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{currentParentSpec},
			},
		},
		Status: gatewayv1.HTTPRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{
					{
						ParentRef:      ourDetachedParent,
						ControllerName: defaultControllerName,
						Conditions: []metav1.Condition{{
							Type:   string(gatewayv1.RouteConditionAccepted),
							Status: metav1.ConditionFalse,
							Reason: string(gatewayv1.RouteReasonNotAllowedByListeners),
						}},
					},
					{
						ParentRef:      otherControllerDetachedParent,
						ControllerName: gatewayv1.GatewayController("example.com/other-gateway-controller"),
					},
					{
						ParentRef:      currentParentStatus,
						ControllerName: defaultControllerName,
						Conditions: []metav1.Condition{{
							Type:   string(gatewayv1.RouteConditionAccepted),
							Status: metav1.ConditionTrue,
							Reason: string(gatewayv1.RouteReasonAccepted),
						}},
					},
				},
			},
		},
	}

	input := &routechecks.HTTPRouteInput{HTTPRoute: route, ControllerName: defaultControllerName}

	require.Len(t, route.Status.Parents, 3)
	require.Equal(t, ourDetachedParent, route.Status.Parents[0].ParentRef)
	require.Equal(t, otherControllerDetachedParent, route.Status.Parents[1].ParentRef)
	require.Equal(t, currentParentStatus, route.Status.Parents[2].ParentRef)

	acceptedCond := metav1.Condition{
		Type:               string(gatewayv1.RouteConditionAccepted),
		Status:             metav1.ConditionTrue,
		Reason:             string(gatewayv1.RouteReasonAccepted),
		ObservedGeneration: input.HTTPRoute.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	for _, parent := range input.HTTPRoute.Spec.ParentRefs {
		input.SetParentCondition(parent, acceptedCond)
	}

	require.Len(t, route.Status.Parents, 3, "merge alone keeps both detached statuses")
	require.Equal(t, ourDetachedParent, route.Status.Parents[0].ParentRef, "merge alone keeps both detached statuses")
	require.Equal(t, otherControllerDetachedParent, route.Status.Parents[1].ParentRef, "merge alone keeps both detached statuses")
	require.Equal(t, currentParentStatus, route.Status.Parents[2].ParentRef, "merge alone keeps both detached statuses")

	route.Status.Parents = pruneRouteParentStatuses(route.Status.Parents, route.Spec.ParentRefs, defaultControllerName)

	require.Len(t, route.Status.Parents, 2, "prune removes only the detached Cilium-owned status")
	require.Equal(t, otherControllerDetachedParent, route.Status.Parents[0].ParentRef, "prune removes only the detached Cilium-owned status")
	require.Equal(t, gatewayv1.GatewayController("example.com/other-gateway-controller"), route.Status.Parents[0].ControllerName, "prune removes only the detached Cilium-owned status")
	require.Equal(t, currentParentStatus, route.Status.Parents[1].ParentRef, "prune removes only the detached Cilium-owned status")
	require.Equal(t, gatewayv1.GatewayController(defaultControllerName), route.Status.Parents[1].ControllerName, "prune removes only the detached Cilium-owned status")
}

func TestRouteValidationPreservesForeignParentStatuses(t *testing.T) {
	tests := []struct {
		name     string
		httpRule *gatewayv1.HTTPRouteRule
		grpcRule *gatewayv1.GRPCRouteRule
	}{
		{
			name: "HTTPRoute/path-regex",
			httpRule: &gatewayv1.HTTPRouteRule{Matches: []gatewayv1.HTTPRouteMatch{{
				Path: &gatewayv1.HTTPPathMatch{Type: ptr.To(gatewayv1.PathMatchRegularExpression), Value: ptr.To("[")},
			}}},
		},
		{
			name: "HTTPRoute/header-regex",
			httpRule: &gatewayv1.HTTPRouteRule{Matches: []gatewayv1.HTTPRouteMatch{{
				Headers: []gatewayv1.HTTPHeaderMatch{{Name: "x-test", Type: ptr.To(gatewayv1.HeaderMatchRegularExpression), Value: "["}},
			}}},
		},
		{
			name: "HTTPRoute/query-regex",
			httpRule: &gatewayv1.HTTPRouteRule{Matches: []gatewayv1.HTTPRouteMatch{{
				QueryParams: []gatewayv1.HTTPQueryParamMatch{{Name: "test", Type: ptr.To(gatewayv1.QueryParamMatchRegularExpression), Value: "["}},
			}}},
		},
		{
			name: "HTTPRoute/header-modifier",
			httpRule: &gatewayv1.HTTPRouteRule{Filters: []gatewayv1.HTTPRouteFilter{{
				Type:                  gatewayv1.HTTPRouteFilterRequestHeaderModifier,
				RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{Set: []gatewayv1.HTTPHeader{{Name: "Host", Value: "example.com"}}},
			}}},
		},
		{
			name: "GRPCRoute/service-regex",
			grpcRule: &gatewayv1.GRPCRouteRule{Matches: []gatewayv1.GRPCRouteMatch{{
				Method: &gatewayv1.GRPCMethodMatch{Type: ptr.To(gatewayv1.GRPCMethodMatchRegularExpression), Service: ptr.To("[")},
			}}},
		},
		{
			name: "GRPCRoute/method-regex",
			grpcRule: &gatewayv1.GRPCRouteRule{Matches: []gatewayv1.GRPCRouteMatch{{
				Method: &gatewayv1.GRPCMethodMatch{Type: ptr.To(gatewayv1.GRPCMethodMatchRegularExpression), Method: ptr.To("[")},
			}}},
		},
		{
			name: "GRPCRoute/header-regex",
			grpcRule: &gatewayv1.GRPCRouteRule{Matches: []gatewayv1.GRPCRouteMatch{{
				Headers: []gatewayv1.GRPCHeaderMatch{{Name: "x-test", Type: ptr.To(gatewayv1.GRPCHeaderMatchRegularExpression), Value: "["}},
			}}},
		},
		{
			name: "GRPCRoute/header-modifier",
			grpcRule: &gatewayv1.GRPCRouteRule{Filters: []gatewayv1.GRPCRouteFilter{{
				Type:                  gatewayv1.GRPCRouteFilterRequestHeaderModifier,
				RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{Set: []gatewayv1.HTTPHeader{{Name: "Host", Value: "example.com"}}},
			}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const foreignController gatewayv1.GatewayController = "example.com/other-controller"
			parents := []gatewayv1.ParentReference{{Name: "cilium-gw"}, {Name: "other-gw"}}
			foreign := gatewayv1.RouteParentStatus{
				ParentRef: parents[1], ControllerName: foreignController,
				Conditions: []metav1.Condition{{
					Type: "Accepted", Status: metav1.ConditionTrue, Reason: "Accepted",
					ObservedGeneration: 1, LastTransitionTime: metav1.Now(),
				}},
			}
			metadata := metav1.ObjectMeta{Name: "route", Namespace: "default", Generation: 2}
			spec := gatewayv1.CommonRouteSpec{ParentRefs: parents}
			status := gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{*foreign.DeepCopy()}}
			var route client.Object
			if tt.httpRule != nil {
				r := &gatewayv1.HTTPRoute{ObjectMeta: metadata,
					Spec:   gatewayv1.HTTPRouteSpec{CommonRouteSpec: spec, Rules: []gatewayv1.HTTPRouteRule{*tt.httpRule}},
					Status: gatewayv1.HTTPRouteStatus{RouteStatus: status},
				}
				route = r
			} else {
				r := &gatewayv1.GRPCRoute{ObjectMeta: metadata,
					Spec:   gatewayv1.GRPCRouteSpec{CommonRouteSpec: spec, Rules: []gatewayv1.GRPCRouteRule{*tt.grpcRule}},
					Status: gatewayv1.GRPCRouteStatus{RouteStatus: status},
				}
				route = r
			}
			objects := []client.Object{route}
			for name, controller := range map[string]gatewayv1.GatewayController{
				"cilium-gw": defaultControllerName, "other-gw": foreignController,
			} {
				objects = append(objects,
					&gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: name},
						Spec: gatewayv1.GatewayClassSpec{ControllerName: controller}},
					&gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: metadata.Namespace},
						Spec: gatewayv1.GatewaySpec{GatewayClassName: gatewayv1.ObjectName(name),
							Listeners: []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}}}},
				)
			}
			c := fake.NewClientBuilder().
				WithScheme(testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)).
				WithStatusSubresource(route).
				WithObjects(objects...).
				Build()
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(route), route))
			var inputs RouteStatusInputs
			switch r := route.(type) {
			case *gatewayv1.HTTPRoute:
				foreign = *r.Status.Parents[0].DeepCopy()
				inputs.HTTPRoutes = []gatewayv1.HTTPRoute{*r}
			case *gatewayv1.GRPCRoute:
				foreign = *r.Status.Parents[0].DeepCopy()
				inputs.GRPCRoutes = []gatewayv1.GRPCRoute{*r}
			}
			m := NewRouteStatusManager(c, slog.Default(), defaultControllerName, helpers.ResourceConfig{}, nil)
			require.NoError(t, m.SetRouteStatuses(t.Context(), slog.Default(), inputs))
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(route), route))
			var actual []gatewayv1.RouteParentStatus
			switch r := route.(type) {
			case *gatewayv1.HTTPRoute:
				actual = r.Status.Parents
			case *gatewayv1.GRPCRoute:
				actual = r.Status.Parents
			}
			require.Len(t, actual, 2, "validation must not create Cilium status for the foreign Gateway")
			require.Contains(t, actual, foreign, "foreign status must remain unchanged")
			for _, parent := range actual {
				if parent.ControllerName == foreignController {
					continue
				}
				require.Equal(t, gatewayv1.GatewayController(defaultControllerName), parent.ControllerName)
				require.Equal(t, parents[0], parent.ParentRef)
				accepted := meta.FindStatusCondition(parent.Conditions, "Accepted")
				require.NotNil(t, accepted)
				require.Equal(t, metav1.ConditionFalse, accepted.Status)
				require.Equal(t, string(gatewayv1.RouteReasonUnsupportedValue), accepted.Reason)
				require.Equal(t, metadata.Generation, accepted.ObservedGeneration)
			}
		})
	}
}

func Test_setTCPRouteStatusesPrunesDetachedParents(t *testing.T) {
	route := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
		Status: gatewayv1.TCPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
			ParentRef:      gatewayv1.ParentReference{Name: "detached-gateway"},
			ControllerName: gatewayv1.GatewayController(defaultControllerName),
		}}}},
	}
	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithStatusSubresource(&gatewayv1.TCPRoute{}).
		WithObjects(route).
		Build()
	routes := &gatewayv1.TCPRouteList{}
	require.NoError(t, c.List(t.Context(), routes))

	m := NewRouteStatusManager(c, slog.Default(), defaultControllerName, RouteStatusManagerConfig{
		IncludeTCPRoutes:        true,
		IncludeUDPRoutes:        true,
		TCPUDPRouteSupport:      true,
		TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
	})
	require.NoError(t, m.setTCPRouteStatuses(t.Context(), slog.Default(), routes.Items, nil))

	updated := &gatewayv1.TCPRoute{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(route), updated))
	require.Empty(t, updated.Status.Parents)
}

func Test_setUDPRouteStatusesPrunesDetachedParents(t *testing.T) {
	route := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
		Status: gatewayv1.UDPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
			ParentRef:      gatewayv1.ParentReference{Name: "detached-gateway"},
			ControllerName: gatewayv1.GatewayController(defaultControllerName),
		}}}},
	}
	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithStatusSubresource(&gatewayv1.UDPRoute{}).
		WithObjects(route).
		Build()
	routes := &gatewayv1.UDPRouteList{}
	require.NoError(t, c.List(t.Context(), routes))

	m := NewRouteStatusManager(c, slog.Default(), defaultControllerName, RouteStatusManagerConfig{
		IncludeTCPRoutes:        true,
		IncludeUDPRoutes:        true,
		TCPUDPRouteSupport:      true,
		TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
	})
	require.NoError(t, m.setUDPRouteStatuses(t.Context(), slog.Default(), routes.Items, nil))

	updated := &gatewayv1.UDPRoute{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(route), updated))
	require.Empty(t, updated.Status.Parents)
}
