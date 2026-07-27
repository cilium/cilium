// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
)

const testGatewayControllerName = "io.cilium/gateway-controller"

func TestEnqueueRequestForBackendServiceIncludesGRPCTCPAndUDP(t *testing.T) {
	scheme := helpers.TestScheme(helpers.AllOptionalKinds)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-svc",
			Namespace: "default",
		},
	}

	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(testGatewayControllerName),
		},
	}

	grpcGateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
		},
	}

	tcpGateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tcp-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
		},
	}

	udpGateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "udp-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
		},
	}

	grpcRoute := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-route",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "grpc-gateway"}},
			},
			Rules: []gatewayv1.GRPCRouteRule{{
				BackendRefs: []gatewayv1.GRPCBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend-svc"},
					},
				}},
			}},
		},
	}

	tcpRoute := &gatewayv1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tcp-route",
			Namespace: "default",
		},
		Spec: gatewayv1.TCPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "tcp-gateway"}},
			},
			Rules: []gatewayv1.TCPRouteRule{{
				BackendRefs: []gatewayv1.BackendRef{{
					BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend-svc"},
				}},
			}},
		},
	}

	udpRoute := &gatewayv1.UDPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "udp-route",
			Namespace: "default",
		},
		Spec: gatewayv1.UDPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "udp-gateway"}},
			},
			Rules: []gatewayv1.UDPRouteRule{{
				BackendRefs: []gatewayv1.BackendRef{{
					BackendObjectReference: gatewayv1.BackendObjectReference{Name: "backend-svc"},
				}},
			}},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(service, gatewayClass, grpcGateway, tcpGateway, udpGateway, grpcRoute, tcpRoute, udpRoute).
		WithIndex(&gatewayv1.Gateway{}, indexers.ImplementationGatewayIndex, func(rawObj client.Object) []string {
			return []string{testGatewayControllerName}
		}).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.BackendServiceHTTPRouteIndex, func(rawObj client.Object) []string {
			return nil
		}).
		WithIndex(&gatewayv1.TLSRoute{}, indexers.BackendServiceTLSRouteIndex, func(rawObj client.Object) []string {
			return nil
		}).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.BackendServiceGRPCRouteIndex, func(rawObj client.Object) []string {
			route := rawObj.(*gatewayv1.GRPCRoute)
			return []string{types.NamespacedName{
				Namespace: route.Namespace,
				Name:      "backend-svc",
			}.String()}
		}).
		WithIndex(&gatewayv1.TCPRoute{}, indexers.BackendServiceTCPRouteIndex, func(rawObj client.Object) []string {
			route := rawObj.(*gatewayv1.TCPRoute)
			return []string{types.NamespacedName{
				Namespace: route.Namespace,
				Name:      "backend-svc",
			}.String()}
		}).
		WithIndex(&gatewayv1.UDPRoute{}, indexers.BackendServiceUDPRouteIndex, func(rawObj client.Object) []string {
			route := rawObj.(*gatewayv1.UDPRoute)
			return []string{types.NamespacedName{
				Namespace: route.Namespace,
				Name:      "backend-svc",
			}.String()}
		}).
		Build()

	handler := EnqueueRequestForBackendService(fakeClient, scheme, *hivetest.Logger(t), testGatewayControllerName)
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer queue.ShutDown()

	handler.Create(t.Context(), event.TypedCreateEvent[client.Object]{Object: service}, queue)

	var got []types.NamespacedName
	for queue.Len() > 0 {
		item, shutdown := queue.Get()
		require.False(t, shutdown)
		got = append(got, item.NamespacedName)
		queue.Done(item)
	}

	require.ElementsMatch(t, []types.NamespacedName{
		{Namespace: "default", Name: "grpc-gateway"},
		{Namespace: "default", Name: "tcp-gateway"},
		{Namespace: "default", Name: "udp-gateway"},
	}, got)
}
