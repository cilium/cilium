// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwconformanceconfig "sigs.k8s.io/gateway-api/conformance/utils/config"
	gwconformance "sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
)

var (
	gwcFinalizer = "batch.gateway.io/finalizer"
	gwcFixture   = []client.Object{
		&gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: "dummy-gw-class",
			},
			Spec: gatewayv1.GatewayClassSpec{
				ControllerName: "io.cilium/gateway-controller",
			},
		},
		&gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "deleting-gw-class",
				DeletionTimestamp: &metav1.Time{Time: time.Now()},
				Finalizers:        []string{gwcFinalizer},
			},
			Spec: gatewayv1.GatewayClassSpec{
				ControllerName: "io.cilium/gateway-controller",
			},
		},
		&gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "non-matching-gw-class",
				DeletionTimestamp: &metav1.Time{Time: time.Now()},
				Finalizers:        []string{gwcFinalizer},
			},
			Spec: gatewayv1.GatewayClassSpec{
				ControllerName: "not-cilium-controller-name",
			},
		},
	}
)

func Test_gatewayClassReconciler_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(gwcFixture...).
		WithStatusSubresource(&gatewayv1.GatewayClass{}).
		Build()
	r := &gatewayClassReconciler{Client: c, logger: hivetest.Logger(t)}

	t.Run("no gateway class", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name: "non-existing-gw-class",
			},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)
	})

	t.Run("gateway class exists but being deleted", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name: "deleting-gw-class",
			},
		})

		require.NoError(t, err, "Error reconciling gateway class")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")
	})

	t.Run("gateway class exists and active", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: client.ObjectKey{
				Name: "dummy-gw-class",
			},
		})

		require.NoError(t, err, "Error reconciling gateway class")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")
		gwconformance.GWCMustHaveAcceptedConditionTrue(t, c, gwconformanceconfig.DefaultTimeoutConfig(), "dummy-gw-class")

		gwc := &gatewayv1.GatewayClass{}
		err = c.Get(context.Background(), types.NamespacedName{Name: "dummy-gw-class"}, gwc)
		require.NoError(t, err, "Error getting gateway class")
		require.NotZero(t, gwc.Status.SupportedFeatures)
	})

	t.Run("non-matching controller name", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name: "non-matching-gw-class",
			},
		})

		require.NoError(t, err, "Error reconciling gateway class")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		gwc := &gatewayv1.GatewayClass{}
		err = c.Get(context.Background(), types.NamespacedName{Name: "non-matching-gw-class"}, gwc)

		require.NoError(t, err, "Error getting gateway class")
		require.Len(t, gwc.Status.Conditions, 0, "Gateway class should not have any conditions")
	})
}
