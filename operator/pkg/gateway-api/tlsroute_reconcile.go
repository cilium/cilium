// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *tlsRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, tlsRoute,
		logfields.Resource, req.NamespacedName,
	)
	scopedLog.Info("Reconciling TLSRoute")

	// Fetch the TLSRoute instance
	original := &gatewayv1alpha2.TLSRoute{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		scopedLog.ErrorContext(ctx, "Unable to fetch TLSRoute", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Ignore deleted TLSRoute, this can happen when foregroundDeletion is enabled
	if original.GetDeletionTimestamp() != nil {
		return controllerruntime.Success()
	}

	tr := original.DeepCopy()

	// check if this cert is allowed to be used by this gateway
	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to retrieve reference grants: %w", err), tr, original)
	}

	// input for the validators
	i := &routechecks.TLSRouteInput{
		Ctx:      ctx,
		Logger:   scopedLog.With(logfields.Resource, tr),
		Client:   r.Client,
		Grants:   grants,
		TLSRoute: tr,
	}

	// gateway validators
	for _, parent := range tr.Spec.ParentRefs {

		// set acceptance to okay, this wil be overwritten in checks if needed
		i.SetParentCondition(parent, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonAccepted),
			Message: "Accepted TLSRoute",
		})

		// set status to okay, this wil be overwritten in checks if needed
		i.SetAllParentCondition(metav1.Condition{
			Type:    string(gatewayv1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonResolvedRefs),
			Message: "Service reference is valid",
		})

		// run the actual validators
		for _, fn := range []routechecks.CheckWithParentFunc{
			routechecks.CheckGatewayRouteKindAllowed,
			routechecks.CheckGatewayMatchingPorts,
			routechecks.CheckGatewayMatchingHostnames,
			routechecks.CheckGatewayMatchingSection,
			routechecks.CheckGatewayAllowedForNamespace,
		} {
			continueCheck, err := fn(i, parent)
			if err != nil {
				return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply route check: %w", err), tr, original)
			}

			if !continueCheck {
				break
			}
		}

		// backend validators
		for _, fn := range []routechecks.CheckWithParentFunc{
			routechecks.CheckAgainstCrossNamespaceBackendReferences,
			routechecks.CheckBackend,
			routechecks.CheckHasServiceImportSupport,
			routechecks.CheckBackendIsExistingService,
		} {
			continueCheck, err := fn(i, parent)
			if err != nil {
				return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply Gateway check: %w", err), tr, original)
			}

			if !continueCheck {
				break
			}
		}
	}

	if err := r.ensureStatus(ctx, tr, original); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update TLSRoute status: %w", err)
	}

	scopedLog.Info("Successfully reconciled TLSRoute")
	return controllerruntime.Success()
}

func (r *tlsRouteReconciler) ensureStatus(ctx context.Context, new *gatewayv1alpha2.TLSRoute, original *gatewayv1alpha2.TLSRoute) error {
	return r.Client.Status().Patch(ctx, new, client.MergeFrom(original))
}

func (r *tlsRouteReconciler) handleReconcileErrorWithStatus(ctx context.Context, reconcileErr error, new *gatewayv1alpha2.TLSRoute, original *gatewayv1alpha2.TLSRoute) (ctrl.Result, error) {
	if err := r.ensureStatus(ctx, new, original); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update TLSRoute status while handling the reconcile error: %w: %w", reconcileErr, err))
	}

	return controllerruntime.Fail(reconcileErr)
}
