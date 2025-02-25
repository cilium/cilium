// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (r *gatewayClassConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (reconcile.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "gatewayclassconfig",
		logfields.Resource, req.NamespacedName,
	)

	scopedLog.Info("Reconciling GatewayClassConfig")
	original := &v2alpha1.CiliumGatewayClassConfig{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		return controllerruntime.Fail(err)
	}
	gwcc := original.DeepCopy()

	//TODO: Add validations if required for the GatewayClassConfig, especially with Cilium configuration
	setGatewayClassConfigAccepted(gwcc, true)

	if err := r.ensureStatus(ctx, gwcc, original); err != nil {
		scopedLog.ErrorContext(ctx, "Failed to update GatewayClass status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	scopedLog.Info("Successfully reconciled GatewayClass")
	return controllerruntime.Success()
}

func (r *gatewayClassConfigReconciler) ensureStatus(ctx context.Context, gwc *v2alpha1.CiliumGatewayClassConfig,
	original *v2alpha1.CiliumGatewayClassConfig) error {
	return r.Client.Status().Patch(ctx, gwc, client.MergeFrom(original))
}

// setGatewayClassConfigAccepted inserts or updates the Accepted condition
// for the provided GatewayClassConfig.
func setGatewayClassConfigAccepted(gwcc *v2alpha1.CiliumGatewayClassConfig, accepted bool) *v2alpha1.CiliumGatewayClassConfig {
	switch accepted {
	case true:
		gwcc.Status.Conditions = merge(gwcc.Status.Conditions, metav1.Condition{
			Type:               "Accepted",
			Status:             metav1.ConditionTrue,
			Reason:             "Accepted",
			Message:            "Valid GatewayClassConfig",
			ObservedGeneration: gwcc.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		})
	case false:
		gwcc.Status.Conditions = merge(gwcc.Status.Conditions, metav1.Condition{
			Type:               "Accepted",
			Status:             metav1.ConditionFalse,
			Reason:             "Accepted",
			Message:            "Invalid GatewayClassConfig",
			ObservedGeneration: gwcc.GetGeneration(),
			LastTransitionTime: metav1.NewTime(time.Now()),
		})
	}

	return gwcc
}
