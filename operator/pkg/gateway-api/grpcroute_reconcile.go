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
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
//
// The reconciliation loop for GRPCRoute mainly performs checks to make sure that
// the resource is valid and accepted. The Accepted resources will be then included
// in parent Gateway for further processing.
func (r *grpcRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, grpcRoute,
		logfields.ParentResource, req.NamespacedName,
	)
	scopedLog.Info("Reconciling GRPCRoute")

	// Fetch the GRPCRoute instance
	original := &gatewayv1.GRPCRoute{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		scopedLog.ErrorContext(ctx, "Unable to fetch GRPCRoute", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Ignore deleted GRPCRoute, this can happen when foregroundDeletion is enabled
	if original.GetDeletionTimestamp() != nil {
		return controllerruntime.Success()
	}

	gr := original.DeepCopy()

	// check if the backend is allowed
	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to retrieve reference grants: %w", err), original, gr)
	}

	// input for the validators
	i := &routechecks.GRPCRouteInput{
		Ctx:       ctx,
		Logger:    scopedLog.With(logfields.Resource, gr),
		Client:    r.Client,
		Grants:    grants,
		GRPCRoute: gr,
	}

	// gateway validators
	for _, parent := range gr.Spec.ParentRefs {
		// set acceptance to okay, this wil be overwritten in checks if needed
		i.SetParentCondition(parent, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonAccepted),
			Message: "Accepted GRPCRoute",
		})

		// set status to okay, this wil be overwritten in checks if needed
		i.SetAllParentCondition(metav1.Condition{
			Type:    string(gatewayv1beta1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1beta1.RouteReasonResolvedRefs),
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
				return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply Gateway check: %w", err), original, gr)
			}

			if !continueCheck {
				break
			}
		}

		for _, fn := range []routechecks.CheckWithParentFunc{
			routechecks.CheckAgainstCrossNamespaceBackendReferences,
			routechecks.CheckBackend,
			routechecks.CheckHasServiceImportSupport,
			routechecks.CheckBackendIsExistingService,
		} {
			if continueCheck, err := fn(i, parent); err != nil || !continueCheck {
				return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply Backend check: %w", err), gr, original)
			}
		}
	}

	if err := r.ensureStatus(ctx, gr, original); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update GRPCRoute status: %w", err)
	}

	scopedLog.Info("Successfully reconciled GRPCRoute")
	return controllerruntime.Success()
}

func (r *grpcRouteReconciler) ensureStatus(ctx context.Context, gr *gatewayv1.GRPCRoute, original *gatewayv1.GRPCRoute) error {
	return r.Client.Status().Patch(ctx, gr, client.MergeFrom(original))
}

func (r *grpcRouteReconciler) handleReconcileErrorWithStatus(ctx context.Context, reconcileErr error, gr *gatewayv1.GRPCRoute, original *gatewayv1.GRPCRoute) (ctrl.Result, error) {
	if err := r.ensureStatus(ctx, gr, original); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update GRPCRoute status while handling the reconcile error: %w: %w", reconcileErr, err))
	}

	return controllerruntime.Fail(reconcileErr)
}
