// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/loading"
	"github.com/cilium/cilium/operator/pkg/model"
)

func TestRouteAttachmentIsScopedToController(t *testing.T) {
	const controllerName = "example.com/our-controller"
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default"}}
	for _, parentKind := range []gatewayv1.Kind{"Gateway", "ListenerSet", "Service"} {
		for _, tt := range []struct {
			name     string
			owned    metav1.ConditionStatus
			foreign  metav1.ConditionStatus
			attached int
		}{
			{name: "foreign acceptance only", foreign: metav1.ConditionTrue},
			{name: "owned rejection", owned: metav1.ConditionFalse, foreign: metav1.ConditionTrue},
			{name: "owned acceptance", owned: metav1.ConditionTrue, foreign: metav1.ConditionFalse, attached: 1},
		} {
			for _, order := range []string{"foreign-first", "owned-first"} {
				t.Run(string(parentKind)+"/"+tt.name+"/"+order, func(t *testing.T) {
					parent := gatewayv1.ParentReference{Name: "gateway", Kind: ptr.To(parentKind)}
					var listenerSets []gatewayv1.ListenerSet
					var listenerSource *model.FullyQualifiedResource
					switch parentKind {
					case "ListenerSet":
						parent.Name = "listeners"
						listenerSets = []gatewayv1.ListenerSet{{ObjectMeta: metav1.ObjectMeta{Name: "listeners", Namespace: "default"}}}
						listenerSource = &model.FullyQualifiedResource{Kind: "ListenerSet", Name: "listeners", Namespace: "default"}
					case "Service":
						parent.Group = ptr.To(gatewayv1.Group(""))
					}
					parents := []gatewayv1.RouteParentStatus{{
						ParentRef: parent, ControllerName: "example.com/other-controller",
						Conditions: []metav1.Condition{{Type: "Accepted", Status: tt.foreign}},
					}}
					if tt.owned != "" {
						parents = append(parents, gatewayv1.RouteParentStatus{
							ParentRef: parent, ControllerName: controllerName,
							Conditions: []metav1.Condition{{Type: "Accepted", Status: tt.owned}},
						})
					}
					if order == "owned-first" {
						slices.Reverse(parents)
					}
					metadata := metav1.ObjectMeta{Name: "route", Namespace: "default"}
					spec := gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{parent}}
					status := gatewayv1.RouteStatus{Parents: parents}
					inputs := loading.TranslationInputs{
						GatewayClass:         gatewayv1.GatewayClass{Spec: gatewayv1.GatewayClassSpec{ControllerName: controllerName}},
						AttachedListenerSets: listenerSets,
						HTTPRoutes: []gatewayv1.HTTPRoute{{ObjectMeta: metadata,
							Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: spec}, Status: gatewayv1.HTTPRouteStatus{RouteStatus: status}}},
						GRPCRoutes: []gatewayv1.GRPCRoute{{ObjectMeta: metadata,
							Spec: gatewayv1.GRPCRouteSpec{CommonRouteSpec: spec}, Status: gatewayv1.GRPCRouteStatus{RouteStatus: status}}},
						TLSRoutes: []gatewayv1.TLSRoute{{ObjectMeta: metadata,
							Spec: gatewayv1.TLSRouteSpec{CommonRouteSpec: spec}, Status: gatewayv1.TLSRouteStatus{RouteStatus: status}}},
						TCPRoutes: []gatewayv1.TCPRoute{{ObjectMeta: metadata,
							Spec: gatewayv1.TCPRouteSpec{CommonRouteSpec: spec}, Status: gatewayv1.TCPRouteStatus{RouteStatus: status}}},
						UDPRoutes: []gatewayv1.UDPRoute{{ObjectMeta: metadata,
							Spec: gatewayv1.UDPRouteSpec{CommonRouteSpec: spec}, Status: gatewayv1.UDPRouteStatus{RouteStatus: status}}},
					}
					if parentKind == "Service" {
						r := &gammaReconciler{controllerName: controllerName}
						svc := &corev1.Service{ObjectMeta: gw.ObjectMeta}
						assert.Len(t, r.filterHTTPRoutesByService(svc, inputs.HTTPRoutes), tt.attached)
						assert.Len(t, r.filterGRPCRoutesByService(svc, inputs.GRPCRoutes), tt.attached)
						return
					}

					for kind, count := range map[string]int{
						"HTTPRoute": len(inputs.AttachedHTTPRoutes(gw)),
						"GRPCRoute": len(inputs.AttachedGRPCRoutes(gw)),
						"TLSRoute":  len(inputs.AttachedTLSRoutes(gw)),
						"TCPRoute":  len(inputs.AttachedTCPRoutes(gw)),
						"UDPRoute":  len(inputs.AttachedUDPRoutes(gw)),
					} {
						assert.Equal(t, tt.attached, count, kind)
					}

					manager := NewListenerStatusManager(nil, nil, controllerName, helpers.ResourceConfig{})
					for _, listener := range []struct {
						protocol gatewayv1.ProtocolType
						routes   int32
					}{
						{protocol: gatewayv1.HTTPProtocolType, routes: 2},
						{protocol: gatewayv1.TLSProtocolType, routes: 1},
						{protocol: gatewayv1.TCPProtocolType, routes: 1},
						{protocol: gatewayv1.UDPProtocolType, routes: 1},
					} {
						count := manager.countAttachedRoutes(gw,
							&gatewayv1.Listener{Name: "listener", Protocol: listener.protocol, Port: 80}, listenerSource,
							inputs.HTTPRoutes, inputs.TLSRoutes, inputs.GRPCRoutes, inputs.TCPRoutes, inputs.UDPRoutes,
							helpers.NewNamespaceLabelIndex(nil), listenerSets...)
						assert.Equal(t, int32(tt.attached)*listener.routes, count, listener.protocol)
					}
				})
			}
		}
	}
}
