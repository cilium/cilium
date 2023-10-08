// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *grpcRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: grpcRoute,
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Reconciling GRPCRoute")

	// Fetch the GRPCRoute instance
	original := &gatewayv1alpha2.GRPCRoute{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return success()
		}
		scopedLog.WithError(err).Error("Unable to fetch GRPCRoute")
		return fail(err)
	}

	// Ignore deleted GRPCRoute, this can happen when foregroundDeletion is enabled
	if original.GetDeletionTimestamp() != nil {
		return success()
	}

	gr := original.DeepCopy()
	defer func() {
		if err := r.updateStatus(ctx, original, gr); err != nil {
			scopedLog.WithError(err).Error("Failed to update GRPCRoute status")
		}
	}()

	// no-op for now
	scopedLog.Info("Successfully reconciled GRPCRoute")
	return success()
}

func (r *grpcRouteReconciler) updateStatus(ctx context.Context, original *gatewayv1alpha2.GRPCRoute, new *gatewayv1alpha2.GRPCRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	opts := cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")
	if cmp.Equal(oldStatus, newStatus, opts) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}
