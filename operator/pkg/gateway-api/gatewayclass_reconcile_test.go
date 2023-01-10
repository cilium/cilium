// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

var gwcFixture = []client.Object{
	&gatewayv1beta1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dummy-gw-class",
		},
		Spec: gatewayv1beta1.GatewayClassSpec{
			ControllerName: "io.cilium/gateway-controller",
		},
	},
	&gatewayv1beta1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deleting-gw-class",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
		},
		Spec: gatewayv1beta1.GatewayClassSpec{
			ControllerName: "io.cilium/gateway-controller",
		},
	},
	&gatewayv1beta1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "non-matching-gw-class",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
		},
		Spec: gatewayv1beta1.GatewayClassSpec{
			ControllerName: "not-cilium-controller-name",
		},
	},
}

func Test_gatewayClassReconciler_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gwcFixture...).Build()
	r := &gatewayClassReconciler{Client: c}

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
			NamespacedName: types.NamespacedName{
				Name: "dummy-gw-class",
			},
		})

		require.NoError(t, err, "Error reconciling gateway class")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")
		GWCMustBeAccepted(t, c, "dummy-gw-class", 5)
	})

	t.Run("non-matching controller name", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name: "non-matching-gw-class",
			},
		})

		require.NoError(t, err, "Error reconciling gateway class")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		gwc := &gatewayv1beta1.GatewayClass{}
		err = c.Get(context.Background(), types.NamespacedName{Name: "non-matching-gw-class"}, gwc)

		require.NoError(t, err, "Error getting gateway class")
		require.Len(t, gwc.Status.Conditions, 0, "Gateway class should not have any conditions")
	})
}

// GWCMustBeAccepted is same as upstream helper function but with v1beta1 instead of v1alpha2
// https://github.com/kubernetes-sigs/gateway-api/blob/main/conformance/utils/kubernetes/helpers.go#L69
func GWCMustBeAccepted(t *testing.T, c client.Client, gwcName string, seconds int) string {
	t.Helper()

	var controllerName string
	waitFor := time.Duration(seconds) * time.Second
	waitErr := wait.PollImmediate(1*time.Second, waitFor, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		gwc := &gatewayv1beta1.GatewayClass{}
		err := c.Get(ctx, types.NamespacedName{Name: gwcName}, gwc)
		if err != nil {
			return false, fmt.Errorf("error fetching GatewayClass: %w", err)
		}

		controllerName = string(gwc.Spec.ControllerName)
		// Passing an empty string as the Reason means that any Reason will do.
		return findConditionInList(t, gwc.Status.Conditions, "Accepted", "True", ""), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for %s GatewayClass to have Accepted condition set to True: %v", gwcName, waitErr)

	return controllerName
}
