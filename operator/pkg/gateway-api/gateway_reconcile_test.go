// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/model"
)

var gwFixture = []client.Object{
	// Valid Gateway class
	&gatewayv1beta1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
		Spec: gatewayv1beta1.GatewayClassSpec{
			ControllerName: "io.cilium/gateway-controller",
		},
	},

	// Service for valid HTTPRoute
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dummy-backend",
			Namespace: "default",
		},
	},

	// Service in another namespace
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dummy-backend",
			Namespace: "another-namespace",
		},
	},

	// Valid HTTPRoute
	&gatewayv1beta1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-route",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
				ParentRefs: []gatewayv1beta1.ParentReference{
					{
						Name: "valid-gateway",
					},
				},
			},
			Rules: []gatewayv1beta1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1beta1.HTTPBackendRef{
						{
							BackendRef: gatewayv1beta1.BackendRef{
								BackendObjectReference: gatewayv1beta1.BackendObjectReference{
									Name: "dummy-backend",
									Port: model.AddressOf[gatewayv1beta1.PortNumber](80),
								},
							},
						},
					},
				},
			},
		},
		Status: gatewayv1beta1.HTTPRouteStatus{
			RouteStatus: gatewayv1beta1.RouteStatus{
				Parents: []gatewayv1beta1.RouteParentStatus{
					{
						ParentRef: gatewayv1beta1.ParentReference{
							Name: "valid-gateway",
						},
						ControllerName: "io.cilium/gateway-controller",
						Conditions: []metav1.Condition{
							{
								Type:   "Accepted",
								Status: "True",
							},
						},
					},
				},
			},
		},
	},

	// Valid gateway
	&gatewayv1beta1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1beta1.GroupName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1beta1.Listener{
				{
					Name:     "http",
					Port:     80,
					Hostname: model.AddressOf[gatewayv1beta1.Hostname]("*.cilium.io"),
					Protocol: "HTTP",
				},
			},
		},
	},

	// gateway with non-existent gateway class
	&gatewayv1beta1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1beta1.GroupName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-with-non-existent-gateway-class",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			GatewayClassName: "non-existent-gateway-class",
			Listeners: []gatewayv1beta1.Listener{
				{
					Name:     "http",
					Port:     80,
					Hostname: model.AddressOf[gatewayv1beta1.Hostname]("*.cilium.io"),
					Protocol: "HTTP",
				},
			},
		},
	},
}

func Test_gatewayReconciler_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gwFixture...).Build()
	r := &gatewayReconciler{Client: c}

	t.Run("non-existent gateway", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: client.ObjectKey{
				Namespace: "default",
				Name:      "non-existent-gateway",
			},
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)
	})

	t.Run("non-existent gateway", func(t *testing.T) {
		key := client.ObjectKey{
			Namespace: "default",
			Name:      "gateway-with-non-existent-gateway-class",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.Error(t, err)
		require.Equal(t, "gatewayclasses.gateway.networking.k8s.io \"non-existent-gateway-class\" not found", err.Error())
		require.Equal(t, ctrl.Result{}, result)

		gw := &gatewayv1beta1.Gateway{}
		err = c.Get(context.Background(), key, gw)
		require.NoError(t, err)
		require.Len(t, gw.Status.Conditions, 1)
		require.Equal(t, "Scheduled", gw.Status.Conditions[0].Type)
		require.Equal(t, metav1.ConditionFalse, gw.Status.Conditions[0].Status)
		require.Equal(t, "NoResources", gw.Status.Conditions[0].Reason)
		require.Equal(t, "GatewayClass does not exist", gw.Status.Conditions[0].Message)
	})

	t.Run("valid gateway", func(t *testing.T) {
		key := client.ObjectKey{
			Namespace: "default",
			Name:      "valid-gateway",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})

		// First reconcile should wait for LB status
		require.Error(t, err)
		require.Equal(t, "load balancer status is not ready", err.Error())
		require.Equal(t, ctrl.Result{}, result)

		// Simulate LB service update
		lb := &corev1.Service{}
		err = c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "cilium-gateway-valid-gateway"}, lb)
		require.NoError(t, err)
		require.Equal(t, corev1.ServiceTypeLoadBalancer, lb.Spec.Type)
		require.Equal(t, "valid-gateway", lb.Labels["io.cilium.gateway/owning-gateway"])

		// Update LB status
		lb.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
			{
				IP: "10.10.10.10",
				Ports: []corev1.PortStatus{
					{
						Port:     80,
						Protocol: "TCP",
					},
				},
			},
		}
		err = c.Status().Update(context.Background(), lb)
		require.NoError(t, err)

		// Perform second reconciliation
		result, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		// Check that the gateway status has been updated
		gw := &gatewayv1beta1.Gateway{}
		err = c.Get(context.Background(), key, gw)
		require.NoError(t, err)

		require.Len(t, gw.Status.Conditions, 2)
		require.Equal(t, "Scheduled", gw.Status.Conditions[0].Type)
		require.Equal(t, "True", string(gw.Status.Conditions[0].Status))
		require.Equal(t, "Gateway successfully scheduled", gw.Status.Conditions[0].Message)
		require.Equal(t, "Ready", gw.Status.Conditions[1].Type)
		require.Equal(t, "True", string(gw.Status.Conditions[1].Status))
		require.Equal(t, "Gateway successfully reconciled", gw.Status.Conditions[1].Message)

		require.Len(t, gw.Status.Addresses, 1)
		require.Equal(t, "IPAddress", string(*gw.Status.Addresses[0].Type))
		require.Equal(t, "10.10.10.10", gw.Status.Addresses[0].Value)

		require.Len(t, gw.Status.Listeners, 1)
		require.Equal(t, "http", string(gw.Status.Listeners[0].Name))
		require.Len(t, gw.Status.Listeners[0].Conditions, 1)
		require.Equal(t, "Ready", gw.Status.Listeners[0].Conditions[0].Type)
		require.Equal(t, "True", string(gw.Status.Listeners[0].Conditions[0].Status))
		require.Equal(t, "Ready", gw.Status.Listeners[0].Conditions[0].Reason)
		require.Equal(t, "Listener Ready", gw.Status.Listeners[0].Conditions[0].Message)
	})

}
