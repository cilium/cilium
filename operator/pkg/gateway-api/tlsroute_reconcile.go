// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

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

	// backend validators
	for _, fn := range []backendValidationFunc{
		checkAgainstCrossNamespaceReferences,
		checkBackendIsService,
		checkBackendIsExistingService,
	} {
		if res, continueCheck, err := fn(ctx, scopedLog.WithField(logfields.Resource, tr), r.Client, tr); err != nil || !continueCheck {
			return res, err
		}
	}

	// gateway validators
	for _, parent := range tr.Spec.ParentRefs {
		ns := namespaceDerefOr(parent.Namespace, tr.GetNamespace())
		gw := &gatewayv1beta1.Gateway{}

		if err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: string(parent.Name)}, gw); err != nil {

			// pass the error to the status
			mergeTLSRouteStatusConditions(tr, parent, []metav1.Condition{
				tlsRouteAcceptedCondition(tr, false, err.Error()),
			})

			if !k8serrors.IsNotFound(err) {
				// if it is not just a not found error, we should return the error as something is bad
				return fail(err)
			}

			// Gateway does not exist skip further checks
			continue
		}

		// run the actual validators
		for _, fn := range []gatewayParentValidatonFunc{
			checkGatewayAllowedForNamespace,
			checkGatewayRouteKindAllowed,
			checkMatchingGatewayPorts,
			checkMatchingGatewayHostnames,
		} {
			if res, continueCheck, err := fn(ctx, scopedLog.WithField(logfields.Resource, tr), r.Client, parent, gw, tr); err != nil || !continueCheck {
				return res, err
			}
		}

		// Gateway is attachable, update the status for this HTTPRoute
		mergeTLSRouteStatusConditions(tr, parent, []metav1.Condition{
			tlsRouteAcceptedCondition(tr, true, tlsRouteAcceptedMessage),
		})
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
