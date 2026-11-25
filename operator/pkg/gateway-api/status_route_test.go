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
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
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
				r := &gatewayv1.HTTPRoute{
					ObjectMeta: metadata,
					Spec:       gatewayv1.HTTPRouteSpec{CommonRouteSpec: spec, Rules: []gatewayv1.HTTPRouteRule{*tt.httpRule}},
					Status:     gatewayv1.HTTPRouteStatus{RouteStatus: status},
				}
				route = r
			} else {
				r := &gatewayv1.GRPCRoute{
					ObjectMeta: metadata,
					Spec:       gatewayv1.GRPCRouteSpec{CommonRouteSpec: spec, Rules: []gatewayv1.GRPCRouteRule{*tt.grpcRule}},
					Status:     gatewayv1.GRPCRouteStatus{RouteStatus: status},
				}
				route = r
			}
			objects := []client.Object{route}
			for name, controller := range map[string]gatewayv1.GatewayController{
				"cilium-gw": defaultControllerName, "other-gw": foreignController,
			} {
				objects = append(objects,
					&gatewayv1.GatewayClass{
						ObjectMeta: metav1.ObjectMeta{Name: name},
						Spec:       gatewayv1.GatewayClassSpec{ControllerName: controller},
					},
					&gatewayv1.Gateway{
						ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: metadata.Namespace},
						Spec: gatewayv1.GatewaySpec{
							GatewayClassName: gatewayv1.ObjectName(name),
							Listeners:        []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
						},
					},
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

func TestHTTPRouteStatusRejectsNamespaceOnIneligibleListeners(t *testing.T) {
	const hostname = "app.example.test"
	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: defaultControllerName},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "infra"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Protocol: gatewayv1.HTTPProtocolType,
					Port:     8443,
					Hostname: new(gatewayv1.Hostname("*.example.test")),
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{From: new(gatewayv1.NamespacesFromSame)},
					},
				},
				{
					Name:     "https",
					Protocol: gatewayv1.HTTPSProtocolType,
					Port:     8443,
					Hostname: new(gatewayv1.Hostname(hostname)),
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode:            new(gatewayv1.TLSModeTerminate),
						CertificateRefs: []gatewayv1.SecretObjectReference{{Name: "gateway-tls"}},
					},
				},
			},
		},
	}
	checkRejection := func(t *testing.T, gateway *gatewayv1.Gateway, section *gatewayv1.SectionName, reason gatewayv1.RouteConditionReason) {
		t.Helper()
		parentRef := gatewayv1.ParentReference{
			Name:        gatewayv1.ObjectName(gateway.Name),
			Namespace:   new(gatewayv1.Namespace(gateway.Namespace)),
			SectionName: section,
		}
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "apps", Generation: 2},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{parentRef}},
				Hostnames:       []gatewayv1.Hostname{hostname},
			},
		}

		ctx := t.Context()
		c := fake.NewClientBuilder().
			WithScheme(testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)).
			WithStatusSubresource(route).
			WithObjects(gwClass, gateway, route).
			Build()
		key := client.ObjectKeyFromObject(route)
		require.NoError(t, c.Get(ctx, key, route))

		m := NewRouteStatusManager(c, slog.Default(), defaultControllerName, helpers.ResourceConfig{}, nil)
		require.NoError(t, m.SetRouteStatuses(ctx, slog.Default(), RouteStatusInputs{HTTPRoutes: []gatewayv1.HTTPRoute{*route}}))
		require.NoError(t, c.Get(ctx, key, route))

		require.Len(t, route.Status.Parents, 1)
		parent := route.Status.Parents[0]
		require.Equal(t, parentRef, parent.ParentRef)
		require.Equal(t, gatewayv1.GatewayController(defaultControllerName), parent.ControllerName)
		accepted := meta.FindStatusCondition(parent.Conditions, string(gatewayv1.RouteConditionAccepted))
		require.NotNil(t, accepted)
		require.Equal(t, route.Generation, accepted.ObservedGeneration)
		require.Equal(t, metav1.ConditionFalse, accepted.Status, "reason: %s", accepted.Reason)
		require.Equal(t, string(reason), accepted.Reason)
	}

	t.Run("HTTP listener is not shadowed by HTTPS hostname", func(t *testing.T) {
		checkRejection(t, gw, new(gatewayv1.SectionName("http")), gatewayv1.RouteReasonNotAllowedByListeners)
	})

	tlsGateway := gw.DeepCopy()
	tlsGateway.Spec.Listeners[0].Hostname = new(gatewayv1.Hostname(hostname))
	tlsGateway.Spec.Listeners[1] = gatewayv1.Listener{
		Name:     "tls",
		Port:     8443,
		Protocol: gatewayv1.TLSProtocolType,
		Hostname: new(gatewayv1.Hostname("*.example.test")),
		TLS:      &gatewayv1.ListenerTLSConfig{Mode: new(gatewayv1.TLSModePassthrough)},
		AllowedRoutes: &gatewayv1.AllowedRoutes{
			Namespaces: &gatewayv1.RouteNamespaces{From: new(gatewayv1.NamespacesFromAll)},
		},
	}
	t.Run("TLS listener cannot allow a route targeting the Gateway", func(t *testing.T) {
		checkRejection(t, tlsGateway, nil, gatewayv1.RouteReasonNotAllowedByListeners)
	})
	t.Run("TLS listener cannot allow an HTTPRoute targeting its section", func(t *testing.T) {
		checkRejection(t, tlsGateway, new(gatewayv1.SectionName("tls")), gatewayv1.RouteReasonNotAllowedByListeners)
	})

	grpcGateway := gw.DeepCopy()
	exactListener := &grpcGateway.Spec.Listeners[1]
	exactListener.Name = "grpc"
	exactListener.Protocol = gatewayv1.HTTPProtocolType
	exactListener.TLS = nil
	exactListener.AllowedRoutes = grpcGateway.Spec.Listeners[0].AllowedRoutes.DeepCopy()
	exactListener.AllowedRoutes.Kinds = []gatewayv1.RouteGroupKind{{Kind: "GRPCRoute"}}
	t.Run("GRPCRoute-only listener shares a port with an HTTPRoute listener", func(t *testing.T) {
		checkRejection(t, grpcGateway, nil, gatewayv1.RouteReasonNotAllowedByListeners)
	})
	t.Run("only the GRPCRoute listener matches the hostname", func(t *testing.T) {
		gateway := grpcGateway.DeepCopy()
		gateway.Spec.Listeners[0].Hostname = new(gatewayv1.Hostname("different.example.test"))
		checkRejection(t, gateway, nil, gatewayv1.RouteReasonNoMatchingListenerHostname)
	})

	t.Run("GRPCRoute-only listener cannot allow an HTTPRoute on another port", func(t *testing.T) {
		gateway := gw.DeepCopy()
		gateway.Spec.Listeners[0].Hostname = new(gatewayv1.Hostname(hostname))
		gateway.Spec.Listeners[1] = gatewayv1.Listener{
			Name:     "grpc",
			Port:     8080,
			Protocol: gatewayv1.HTTPProtocolType,
			Hostname: new(gatewayv1.Hostname("*.example.test")),
			AllowedRoutes: &gatewayv1.AllowedRoutes{
				Kinds:      []gatewayv1.RouteGroupKind{{Kind: "GRPCRoute"}},
				Namespaces: &gatewayv1.RouteNamespaces{From: new(gatewayv1.NamespacesFromAll)},
			},
		}
		checkRejection(t, gateway, nil, gatewayv1.RouteReasonNotAllowedByListeners)
	})
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
		WithScheme(testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)).
		WithStatusSubresource(&gatewayv1.TCPRoute{}).
		WithObjects(route).
		Build()
	routes := &gatewayv1.TCPRouteList{}
	require.NoError(t, c.List(t.Context(), routes))

	m := NewRouteStatusManager(c, slog.Default(), defaultControllerName, helpers.ResourceConfig{
		IncludeTCPRoutes:        true,
		IncludeUDPRoutes:        true,
		TCPRouteUDPRouteSupport: true,
		TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
	},
		nil,
	)
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
		WithScheme(testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)).
		WithStatusSubresource(&gatewayv1.UDPRoute{}).
		WithObjects(route).
		Build()
	routes := &gatewayv1.UDPRouteList{}
	require.NoError(t, c.List(t.Context(), routes))

	m := NewRouteStatusManager(c, slog.Default(), defaultControllerName, helpers.ResourceConfig{
		IncludeTCPRoutes:        true,
		IncludeUDPRoutes:        true,
		TCPRouteUDPRouteSupport: true,
		TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
	},
		nil,
	)
	require.NoError(t, m.setUDPRouteStatuses(t.Context(), slog.Default(), routes.Items, nil))

	updated := &gatewayv1.UDPRoute{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(route), updated))
	require.Empty(t, updated.Status.Parents)
}
