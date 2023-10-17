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
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *tlsRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: "tlsRoute",
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Reconciling TLSRoute")

	// Fetch the TLSRoute instance
	original := &gatewayv1alpha2.TLSRoute{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return success()
		}
		scopedLog.WithError(err).Error("Unable to fetch TLSRoute")
		return fail(err)
	}

	// Ignore deleted TLSRoute, this can happen when foregroundDeletion is enabled
	if original.GetDeletionTimestamp() != nil {
		return success()
	}

	tr := original.DeepCopy()
	defer func() {
		if err := r.updateStatus(ctx, original, tr); err != nil {
			scopedLog.WithError(err).Error("Failed to update TLSRoute status")
		}
	}()

	// check if this cert is allowed to be used by this gateway
	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return fail(fmt.Errorf("failed to retrieve reference grants: %w", err))
	}

	// input for the validators
	i := &routechecks.TLSRouteInput{
		Ctx:      ctx,
		Logger:   scopedLog.WithField(logfields.Resource, tr),
		Client:   r.Client,
		Grants:   grants,
		TLSRoute: tr,
	}

	// gateway validators
	for _, parent := range tr.Spec.ParentRefs {

		// set acceptance to okay, this wil be overwritten in checks if needed
		i.SetParentCondition(parent, metav1.Condition{
			Type:    conditionStatusAccepted,
			Status:  metav1.ConditionTrue,
			Reason:  conditionReasonAccepted,
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

	// backend validators

	for _, fn := range []routechecks.CheckRuleFunc{
		routechecks.CheckAgainstCrossNamespaceBackendReferences,
		routechecks.CheckBackendIsService,
		routechecks.CheckBackendIsExistingService,
	} {
		if continueCheck, err := fn(i); err != nil || !continueCheck {
			return ctrl.Result{}, err
		}
	}

	scopedLog.Info("Successfully reconciled TLSRoute")
	return success()
}

func (r *tlsRouteReconciler) updateStatus(ctx context.Context, original *gatewayv1alpha2.TLSRoute, new *gatewayv1alpha2.TLSRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	opts := cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")
	if cmp.Equal(oldStatus, newStatus, opts) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}
