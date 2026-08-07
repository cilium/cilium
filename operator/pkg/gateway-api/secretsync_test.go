// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
)

const testGatewayControllerName = "io.cilium/gateway-controller"

func TestSecretSyncHandlerEnqueueListenerSetTLSSecretsIncludingCrossNamespaceRefs(t *testing.T) {
	gatewayClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(testGatewayControllerName),
		},
	}

	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "parent-gateway",
			Namespace: "gw-ns",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
		},
	}

	listenerSet := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-listeners",
			Namespace: "ls-secret-ns",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name:      gatewayv1.ObjectName(gateway.Name),
				Namespace: ptr.To[gatewayv1.Namespace](gatewayv1.Namespace(gateway.Namespace)),
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Name: "default-secret",
							},
							{
								Name:      "cross-ns-secret",
								Namespace: ptr.To[gatewayv1.Namespace]("cross-secret-ns"),
							},
						},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)).
		WithObjects(gatewayClass, gateway, listenerSet).
		Build()

	handler := NewSecretSyncHandler(fakeClient, hivetest.Logger(t), testGatewayControllerName)
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer queue.ShutDown()

	handler.EnqueueListenerSetTLSSecrets().Create(t.Context(), event.TypedCreateEvent[client.Object]{Object: listenerSet}, queue)

	var got []types.NamespacedName
	for queue.Len() > 0 {
		item, shutdown := queue.Get()
		require.False(t, shutdown)
		got = append(got, item.NamespacedName)
		queue.Done(item)
	}

	require.ElementsMatch(t, []types.NamespacedName{
		{Namespace: "ls-secret-ns", Name: "default-secret"},
		{Namespace: "cross-secret-ns", Name: "cross-ns-secret"},
	}, got)
}
