// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
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
func (r *gammaHttpRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// TODO: This currently is copied from the HTTPRoute reconciler, which just
	// checks that HTTPRoutes are good before marking them as okay.
	// For GAMMA objects, we need to work more like the _Gateway_ reconciler
	// which checks things, builds a model, then calls the translation function
	// after populating the Input struct with the relevant objects from
	// controller-runtime cache.

	// FOR NOW, though, this should just log things and update status if they reconcile
	// preferably with big GAMMA reconciler tags.
	//
	// Then, I write the ingestion part to ingest GAMMA stuff into a model
	// Then, we test the translation part works
	// Then we put it all in here.
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: "gammaHttpRoute",
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Reconciling GAMMA HTTPRoute")

	// Fetch the HTTPRoute instance
	original := &gatewayv1.HTTPRoute{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		scopedLog.WithError(err).Error("Unable to fetch HTTPRoute")
		return controllerruntime.Fail(err)
	}

	// Ignore deleted HTTPRoute, this can happen when foregroundDeletion is enabled
	if original.GetDeletionTimestamp() != nil {
		return controllerruntime.Success()
	}

	hr := original.DeepCopy()

	// check if this cert is allowed to be used by this gateway
	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to retrieve reference grants: %w", err), original, hr)
	}

	// input for the validators
	i := &routechecks.HTTPRouteInput{
		Ctx:       ctx,
		Logger:    scopedLog.WithField(logfields.Resource, hr),
		Client:    r.Client,
		Grants:    grants,
		HTTPRoute: hr,
	}

	// gateway validators
	for _, parent := range hr.Spec.ParentRefs {

		// set acceptance to okay, this wil be overwritten in checks if needed
		i.SetParentCondition(parent, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonAccepted),
			Message: "Accepted HTTPRoute",
		})

		// set status to okay, this wil be overwritten in checks if needed
		i.SetAllParentCondition(metav1.Condition{
			Type:    string(gatewayv1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonResolvedRefs),
			Message: "Service reference is valid",
		})

		for _, fn := range []routechecks.CheckParentFunc{
			routechecks.CheckGammaServiceAllowedForNamespace,
		} {
			continueCheck, err := fn(i, parent)
			if err != nil {
				return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply Gateway check: %w", err), original, hr)
			}

			if !continueCheck {
				break
			}
		}
	}

	for _, fn := range []routechecks.CheckRuleFunc{
		routechecks.CheckAgainstCrossNamespaceBackendReferences,
		routechecks.CheckBackend,
		routechecks.CheckBackendIsExistingService,
	} {
		continueCheck, err := fn(i)
		if err != nil {
			return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply Backend check: %w", err), original, hr)
		}

		if !continueCheck {
			break
		}
	}

	if err := r.updateStatus(ctx, original, hr); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update HTTPRoute status: %w", err)
	}

	scopedLog.Info("Successfully reconciled HTTPRoute")
	return controllerruntime.Success()
}

func (r *gammaHttpRouteReconciler) updateStatus(ctx context.Context, original *gatewayv1.HTTPRoute, new *gatewayv1.HTTPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	opts := cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")
	if cmp.Equal(oldStatus, newStatus, opts) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}

func (r *gammaHttpRouteReconciler) handleReconcileErrorWithStatus(ctx context.Context, reconcileErr error, original *gatewayv1.HTTPRoute, modified *gatewayv1.HTTPRoute) (ctrl.Result, error) {
	if err := r.updateStatus(ctx, original, modified); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update HTTPRoute status while handling the reconcile error: %w: %w", reconcileErr, err))
	}

	return controllerruntime.Fail(reconcileErr)
}
