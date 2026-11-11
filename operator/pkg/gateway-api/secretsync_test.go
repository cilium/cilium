// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
	syncnames "github.com/cilium/cilium/pkg/secretsync/names"
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

func TestSessionTicketSecretRotation(t *testing.T) {
	clock := clocktesting.NewFakeClock(time.Date(2026, time.November, 10, 0, 0, 0, 0, time.UTC))
	gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
		Namespace: "tenant", Name: "gateway", UID: "gateway-uid",
	}, Spec: gatewayv1.GatewaySpec{GatewayClassName: "cilium"}}
	gatewayClass := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec: gatewayv1.GatewayClassSpec{ControllerName: defaultControllerName}}
	k8sClient := fake.NewClientBuilder().
		WithScheme(testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)).
		WithObjects(gateway, gatewayClass).Build()
	request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gateway)}
	secretKey := types.NamespacedName{
		Namespace: "gateway-secrets", Name: syncnames.GatewaySessionTicketSecretName(gateway.UID),
	}
	reconcileSecret := func() (*corev1.Secret, time.Duration) {
		t.Helper()
		controller := &sessionTicketReconciler{
			client: k8sClient, namespace: secretKey.Namespace, rotationInterval: time.Hour, clock: clock,
		}
		result, err := controller.Reconcile(t.Context(), request)
		require.NoError(t, err)
		secret := &corev1.Secret{}
		require.NoError(t, k8sClient.Get(t.Context(), secretKey, secret))
		return secret, result.RequeueAfter
	}

	initial, nextRotation := reconcileSecret()
	require.Equal(t, corev1.SecretTypeOpaque, initial.Type)
	require.Len(t, initial.Data, 1)
	require.Len(t, initial.Data["tls.sessionticket.key"], 80)
	require.NotEqual(t, make([]byte, 80), initial.Data["tls.sessionticket.key"])
	require.Equal(t, time.Hour, nextRotation)
	rotatedAt, err := time.Parse(time.RFC3339Nano, initial.Annotations["gateway.cilium.io/session-ticket-key-rotated-at"])
	require.NoError(t, err)
	require.True(t, clock.Now().Equal(rotatedAt))

	clock.Step(30 * time.Minute)
	unchanged, nextRotation := reconcileSecret()
	require.Equal(t, initial, unchanged, "a new controller must preserve the stored key before its deadline")
	require.Equal(t, 30*time.Minute, nextRotation)

	clock.Step(30 * time.Minute)
	rotated, nextRotation := reconcileSecret()
	require.Len(t, rotated.Data, 2)
	require.Len(t, rotated.Data["tls.sessionticket.key"], 80)
	require.NotEqual(t, initial.Data["tls.sessionticket.key"], rotated.Data["tls.sessionticket.key"])
	require.Equal(t, initial.Data["tls.sessionticket.key"], rotated.Data["tls.sessionticket.key.1"])
	require.Equal(t, time.Hour, nextRotation)
	require.NotEqual(t, initial.Annotations, rotated.Annotations)

	clock.Step(time.Hour)
	secondRotation, nextRotation := reconcileSecret()
	require.Len(t, secondRotation.Data, 2)
	require.Len(t, secondRotation.Data["tls.sessionticket.key"], 80)
	require.NotEqual(t, rotated.Data["tls.sessionticket.key"], secondRotation.Data["tls.sessionticket.key"])
	require.Equal(t, rotated.Data["tls.sessionticket.key"], secondRotation.Data["tls.sessionticket.key.1"])
	require.NotContains(t, secondRotation.Data, "tls.sessionticket.key.2")
	require.Equal(t, time.Hour, nextRotation)
}

func TestSessionTicketSecretIsolation(t *testing.T) {
	gatewayClass := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec: gatewayv1.GatewayClassSpec{ControllerName: defaultControllerName}}
	k8sClient := fake.NewClientBuilder().
		WithScheme(testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)).
		WithObjects(gatewayClass).Build()
	controller := &sessionTicketReconciler{
		client: k8sClient, namespace: "gateway-secrets", rotationInterval: time.Hour,
		clock: clocktesting.NewFakeClock(time.Now()),
	}
	var keys [][]byte
	for _, identity := range []struct {
		namespace string
		uid       types.UID
	}{{"tenant-a", "gateway-a"}, {"tenant-b", "gateway-b"}, {"tenant-a", "gateway-recreated"}} {
		gateway := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{
			Namespace: identity.namespace, Name: "gateway", UID: identity.uid,
		}, Spec: gatewayv1.GatewaySpec{GatewayClassName: "cilium"}}
		require.NoError(t, k8sClient.Create(t.Context(), gateway))
		request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gateway)}
		_, err := controller.Reconcile(t.Context(), request)
		require.NoError(t, err)
		secret := &corev1.Secret{}
		require.NoError(t, k8sClient.Get(t.Context(), types.NamespacedName{
			Namespace: "gateway-secrets", Name: syncnames.GatewaySessionTicketSecretName(gateway.UID),
		}, secret))
		for _, previous := range keys {
			require.NotEqual(t, previous, secret.Data["tls.sessionticket.key"])
		}
		keys = append(keys, secret.Data["tls.sessionticket.key"])
		require.NoError(t, k8sClient.Delete(t.Context(), gateway))
		_, err = controller.Reconcile(t.Context(), request)
		require.NoError(t, err)
	}
	secrets := &corev1.SecretList{}
	require.NoError(t, k8sClient.List(t.Context(), secrets))
	require.Len(t, secrets.Items, 3)
}
