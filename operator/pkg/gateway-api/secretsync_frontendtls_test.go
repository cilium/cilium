// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func TestFrontendTLSConfigMapSyncUsesOnlyFirstRef(t *testing.T) {
	logger := hivetest.Logger(t)

	gw := gatewayWithFrontendTLSConfigMapRefs("gateway", []gatewayv1.ObjectReference{
		{Group: "", Kind: "ConfigMap", Name: "first-ca"},
		{Group: "", Kind: "ConfigMap", Name: "ignored-ca"},
	})
	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithObjects(
			&gatewayv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
				Spec: gatewayv1.GatewayClassSpec{
					ControllerName: defaultControllerName,
				},
			},
			gw,
		).
		Build()
	handler := NewSecretSyncHandler(c, logger, defaultControllerName)

	firstCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "first-ca"},
	}
	ignoredCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ignored-ca"},
	}

	require.True(t, handler.FrontendTLSConfigMapIsReferenced(t.Context(), c, logger, firstCA))
	require.False(t, handler.FrontendTLSConfigMapIsReferenced(t.Context(), c, logger, ignoredCA))

	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	t.Cleanup(queue.ShutDown)

	handler.EnqueueFrontendTLSConfigMaps().Create(t.Context(), event.CreateEvent{Object: gw}, queue)

	require.Equal(t, 1, queue.Len())
	item, shutdown := queue.Get()
	require.False(t, shutdown)
	require.Equal(t, reconcile.Request{NamespacedName: clientObjectKey("default", "first-ca")}, item)
	queue.Done(item)
}

func gatewayWithFrontendTLSConfigMapRefs(name string, refs []gatewayv1.ObjectReference) *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      name,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			TLS: &gatewayv1.GatewayTLSConfig{
				Frontend: &gatewayv1.FrontendTLSConfig{
					Default: gatewayv1.TLSConfig{
						Validation: &gatewayv1.FrontendTLSValidation{
							CACertificateRefs: refs,
						},
					},
				},
			},
		},
	}
}

func clientObjectKey(namespace, name string) types.NamespacedName {
	return types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}
}
