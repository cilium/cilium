// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *gammaHttpRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, gammaHTTPRoute,
		logfields.Resource, req.NamespacedName,
	)
	scopedLog.Info("Reconciling GAMMA HTTPRoute")

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

	// Get ReferenceGrants
	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to retrieve reference grants: %w", err), original, hr)
	}

	servicesList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, servicesList); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list Services", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, hr)
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

		if !helpers.IsGammaService(parent) {
			scopedLog.Debug("Non GAMMA parentRef in GAMMA HTTPRoute reconciliation",
				logfields.Controller, "gammaHttpRoute",
				logfields.Resource, client.ObjectKeyFromObject(hr),
			)
			continue
		}

		// set acceptance to okay, this wil be overwritten in checks if needed
		i.SetParentCondition(parent, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonAccepted),
			Message: "Accepted HTTPRoute",
		})

		// set status to okay, this wil be overwritten in checks if needed
		i.SetParentCondition(parent, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonResolvedRefs),
			Message: "Service reference is valid",
		})

		for _, fn := range []routechecks.CheckWithParentFunc{
			routechecks.CheckGammaServiceAllowedForNamespace,
		} {
			continueCheck, err := fn(i, parent)
			if err != nil {
				return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply parentRef check: %w", err), original, hr)
			}

			if !continueCheck {
				break
			}
		}

		for _, fn := range []routechecks.CheckWithParentFunc{
			routechecks.CheckAgainstCrossNamespaceBackendReferences,
			routechecks.CheckBackend,
			routechecks.CheckBackendIsExistingService,
		} {
			continueCheck, err := fn(i, parent)
			if err != nil {
				return r.handleReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply route rule check: %w", err), original, hr)
			}

			if !continueCheck {
				break
			}
		}

	}

	if err := r.updateStatus(ctx, original, hr); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update HTTPRoute status: %w", err)
	}

	httpListeners := ingestion.GammaHTTPRoutes(r.logger, ingestion.GammaInput{
		HTTPRoutes:      []gatewayv1.HTTPRoute{*hr},
		Services:        servicesList.Items,
		ReferenceGrants: grants.Items,
	})

	cec, svc, cep, err := r.translator.Translate(&model.Model{HTTP: httpListeners})
	if err != nil {
		scopedLog.ErrorContext(ctx, "Unable to translate resources", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, hr)
	}

	scopedLog.DebugContext(ctx, "GAMMA translation result",
		logfields.Service, svc,
		logfields.Endpoint, cep)

	if err = r.ensureEnvoyConfig(ctx, cec); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to ensure CiliumEnvoyConfig", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, hr)
	}

	if err = r.ensureEndpoints(ctx, cep); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to ensure Endpoints", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, hr)
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

func (r *gammaHttpRouteReconciler) ensureEnvoyConfig(ctx context.Context, desired *ciliumv2.CiliumEnvoyConfig) error {
	cec := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, cec, func() error {
		cec.Spec = desired.Spec
		setMergedLabelsAndAnnotations(cec, desired)
		return nil
	})
	return err
}

func (r *gammaHttpRouteReconciler) ensureEndpoints(ctx context.Context, desired *corev1.Endpoints) error {
	ep := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, ep, func() error {
		ep.Subsets = desired.Subsets
		ep.OwnerReferences = desired.OwnerReferences
		setMergedLabelsAndAnnotations(ep, desired)
		return nil
	})
	return err
}
