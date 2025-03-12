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
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *httpRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, httpRoute,
		logfields.Resource, req.NamespacedName,
	)
	scopedLog.Info("Reconciling HTTPRoute")

	// Fetch the HTTPRoute instance
	original := &gatewayv1.HTTPRoute{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		scopedLog.ErrorContext(ctx, "Unable to fetch HTTPRoute", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Ignore deleted HTTPRoute, this can happen when foregroundDeletion is enabled
	if original.GetDeletionTimestamp() != nil {
		return controllerruntime.Success()
	}

	hr := original.DeepCopy()

	if !r.hasMatchingGatewayParent()(hr) {
		scopedLog.Warn("HTTPRoute does not have a matching Gateway Parent, this should not be possible")
		err := fmt.Errorf("Reconciliation failure: somehow selected a HTTPRoute without a matching Gateway parent")
		return controllerruntime.Fail(err)
	}

	// check if this cert is allowed to be used by this gateway
	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to retrieve reference grants: %w", err), original, hr)
	}

	// input for the validators
	i := &routechecks.HTTPRouteInput{
		Ctx:       ctx,
		Logger:    scopedLog.With(logfields.Resource, hr),
		Client:    r.Client,
		Grants:    grants,
		HTTPRoute: hr,
	}

	// gateway validators
	for _, parent := range hr.Spec.ParentRefs {

		// If this parentRef is not a Gateway parentRef, then skip it.
		if !helpers.IsGateway(parent) {
			continue
		}

		// Similarly, if this Gateway is not a matching one, then
		if !r.parentIsMatchingGateway(parent, hr.Namespace) {
			continue
		}

		// set Accepted to okay, this wil be overwritten in checks if needed
		i.SetParentCondition(parent, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonAccepted),
			Message: "Accepted HTTPRoute",
		})

		// set ResolvedRefs to okay, this wil be overwritten in checks if needed
		i.SetParentCondition(parent, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonResolvedRefs),
			Message: "Service reference is valid",
		})

		// run the Gateway validators
		for _, fn := range []routechecks.CheckWithParentFunc{
			routechecks.CheckGatewayRouteKindAllowed,
			routechecks.CheckGatewayMatchingPorts,
			routechecks.CheckGatewayMatchingHostnames,
			routechecks.CheckGatewayMatchingSection,
			routechecks.CheckGatewayAllowedForNamespace,
		} {
			continueCheck, err := fn(i, parent)
			if err != nil {
				return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply Gateway check: %w", err), original, hr)
			}

			if !continueCheck {
				break
			}
		}

		// Run the Rule validators, these need to be run per-parent so that we
		// don't update status for parents we don't own.
		for _, fn := range []routechecks.CheckWithParentFunc{
			routechecks.CheckAgainstCrossNamespaceBackendReferences,
			routechecks.CheckBackend,
			routechecks.CheckHasServiceImportSupport,
			routechecks.CheckBackendIsExistingService,
		} {
			continueCheck, err := fn(i, parent)
			if err != nil {
				return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply Backend check: %w", err), hr, original)
			}

			if !continueCheck {
				break
			}
		}
	}

	if err := r.ensureStatus(ctx, hr, original); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update HTTPRoute status: %w", err)
	}

	scopedLog.Info("Successfully reconciled HTTPRoute")
	return controllerruntime.Success()
}

func (r *httpRouteReconciler) ensureStatus(ctx context.Context, hr *gatewayv1.HTTPRoute, original *gatewayv1.HTTPRoute) error {
	return r.Client.Status().Patch(ctx, hr, client.MergeFrom(original))
}

func (r *httpRouteReconciler) handleReconcileErrorWithStatus(ctx context.Context, reconcileErr error, hr, original *gatewayv1.HTTPRoute) (ctrl.Result, error) {
	if err := r.ensureStatus(ctx, hr, original); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update HTTPRoute status while handling the reconcile error: %w: %w", reconcileErr, err))
	}

	return controllerruntime.Fail(reconcileErr)
}
