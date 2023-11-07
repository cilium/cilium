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
func (r *httpRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: "httpRoute",
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Reconciling HTTPRoute")

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
	defer func() {
		if err := r.updateStatus(ctx, original, hr); err != nil {
			scopedLog.WithError(err).Error("Failed to update HTTPRoute status")
		}
	}()

	// check if this cert is allowed to be used by this gateway
	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to retrieve reference grants: %w", err))
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
			Type:    conditionStatusAccepted,
			Status:  metav1.ConditionTrue,
			Reason:  conditionReasonAccepted,
			Message: "Accepted HTTPRoute",
		})

		// set status to okay, this wil be overwritten in checks if needed
		i.SetAllParentCondition(metav1.Condition{
			Type:    string(gatewayv1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonResolvedRefs),
			Message: "Service reference is valid",
		})

		// run the actual validators
		for _, fn := range []routechecks.CheckGatewayFunc{
			routechecks.CheckGatewayAllowedForNamespace,
			routechecks.CheckGatewayRouteKindAllowed,
			routechecks.CheckGatewayMatchingPorts,
			routechecks.CheckGatewayMatchingHostnames,
			routechecks.CheckGatewayMatchingSection,
		} {
			continueCheck, err := fn(i, parent)
			if err != nil {
				return ctrl.Result{}, err
			}

			if !continueCheck {
				break
			}
		}
	}

	for _, fn := range []routechecks.CheckRuleFunc{
		routechecks.CheckAgainstCrossNamespaceBackendReferences,
		routechecks.CheckBackendIsService,
		routechecks.CheckBackendIsExistingService,
	} {
		if continueCheck, err := fn(i); err != nil || !continueCheck {
			return ctrl.Result{}, err
		}
	}

	scopedLog.Info("Successfully reconciled HTTPRoute")
	return controllerruntime.Success()
}

func (r *httpRouteReconciler) updateStatus(ctx context.Context, original *gatewayv1.HTTPRoute, new *gatewayv1.HTTPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	opts := cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")
	if cmp.Equal(oldStatus, newStatus, opts) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}
