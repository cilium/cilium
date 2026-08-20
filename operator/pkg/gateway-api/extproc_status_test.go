// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/operator/pkg/model"
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
	require.Equal(t, metav1.ConditionTrue, newCondition.Status)
	require.Equal(t, "OrderingConflict", newCondition.Reason)
	require.Equal(t, routeOrderingConflictMessage, newCondition.Message)
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

func TestOverlayExtProcOrderingConflictScopesRouteKindsAndParents(t *testing.T) {
	creation := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	gatewayParent := extProcGatewayParent("gateway", "http", 80)
	listenerSetParent := extProcParent("ListenerSet", "listenerset", "http", 80)
	serviceParent := extProcStatusServiceParent("service-a", 80)
	otherServiceParent := extProcStatusServiceParent("service-b", 80)

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

	grpcRoute := gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "new-grpc", Namespace: "default", UID: "new-grpc-uid", Generation: 1},
		Status: gatewayv1.GRPCRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{
			extProcStatusParent(listenerSetParent, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted),
			extProcStatusParent(gatewayParent, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted),
		}}},
	}
	grpcRoutes := []gatewayv1.GRPCRoute{grpcRoute}
	(&gatewayReconciler{}).overlayExtProcOrderingConflictsInMemory(m, nil, grpcRoutes)
	for _, parent := range grpcRoutes[0].Status.Parents {
		condition := parent.Conditions[0]
		require.Equal(t, metav1.ConditionTrue, condition.Status)
		if parent.ParentRef.Name == listenerSetParent.Name {
			require.Equal(t, "OrderingConflict", condition.Reason)
		} else {
			require.Equal(t, string(gatewayv1.RouteReasonAccepted), condition.Reason)
		}
	}

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
	httpRoute := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "new-http", Namespace: "default", UID: "new-http-uid", Generation: 1},
		Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{
			extProcStatusParent(serviceParent, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted),
			extProcStatusParent(otherServiceParent, metav1.ConditionTrue, gatewayv1.RouteReasonAccepted),
		}}},
	}
	httpRoutes := &gatewayv1.HTTPRouteList{Items: []gatewayv1.HTTPRoute{httpRoute}}
	(&gammaReconciler{}).overlayExtProcOrderingConflictsInMemory(gammaModel, httpRoutes, &gatewayv1.GRPCRouteList{})
	conditions := httpRoutes.Items[0].Status.Parents
	require.Len(t, conditions, 2)
	require.Equal(t, "OrderingConflict", conditions[0].Conditions[0].Reason)
	require.Equal(t, string(gatewayv1.RouteReasonAccepted), conditions[1].Conditions[0].Reason)
}

func extProcStatusFilter(name, routeName string, creation time.Time, filterIndex int) model.ExtensionRefFilter {
	return extProcStatusFilterKind(name, routeName, "HTTPRoute", creation, filterIndex)
}

func extProcStatusFilterKind(name, routeName, kind string, creation time.Time, filterIndex int) model.ExtensionRefFilter {
	return model.ExtensionRefFilter{
		Name:                         name,
		SourceRouteCreationTimestamp: creation,
		SourceRouteFilterIndex:       filterIndex,
		SourceRouteRule: &model.HTTPRouteRule{Source: model.FullyQualifiedResource{
			Name: routeName, Namespace: "default", Kind: kind, UID: routeName + "-uid",
		}},
	}
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
