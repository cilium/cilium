// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// gatewayClassReconciler reconciles a GatewayClass object
type gatewayClassReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Model *internalModel

	controllerName string
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *gatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: "gatewayclass",
		logfields.Resource:   req.NamespacedName,
	})

	scopedLog.Info("Reconciling GatewayClass")
	gwc := &gatewayv1beta1.GatewayClass{}
	if err := r.Client.Get(ctx, req.NamespacedName, gwc); err != nil {
		if k8serrors.IsNotFound(err) {
			return success()
		}
		return fail(err)
	}

	// Ignore deleted GatewayClass, this can happen when foregroundDeletion is enabled
	// The reconciliation loop will automatically kick off for related Gateway resources.
	if gwc.GetDeletionTimestamp() != nil {
		return success()
	}

	// TODO(tam): Support spec.ParametersRef later for different use cases
	// Right now, we will still support multiple gateway class, but no support for parameters.
	// Hence, just set gateway class Accepted condition to true blindly.
	setGatewayClassAccepted(gwc, true)

	if err := r.Client.Status().Update(ctx, gwc); err != nil {
		scopedLog.WithError(err).Error("Failed to update GatewayClass status")
		return fail(err)
	}
	scopedLog.Info("Successfully reconciled GatewayClass")
	return success()
}

// SetupWithManager sets up the controller with the Manager.
func (r *gatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changes to GatewayClass having the same controller name, and
		// not status changes.
		// TODO(tam): Add watch for related configmap once spec.ParametersRef is supported.
		For(&gatewayv1beta1.GatewayClass{}, builder.WithPredicates(predicate.And(
			predicate.NewPredicateFuncs(r.gatewayClassMatched),
			predicate.GenerationChangedPredicate{},
		))).
		Complete(r)
}

func (r *gatewayClassReconciler) gatewayClassMatched(obj client.Object) bool {
	gc, ok := obj.(*gatewayv1beta1.GatewayClass)
	if !ok {
		return false
	}
	if r.controllerName != string(gc.Spec.ControllerName) {
		return false
	}
	return true
}
