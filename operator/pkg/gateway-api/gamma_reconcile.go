// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
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
func (r *gammaReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Resource, req.NamespacedName,
	)
	scopedLog.InfoContext(ctx, "Reconciling GAMMA service")

	// Step 1: Retrieve the Service
	originalSvc := &corev1.Service{}

	if err := r.Client.Get(ctx, req.NamespacedName, originalSvc, &client.GetOptions{}); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		scopedLog.ErrorContext(ctx, "Unable to get Service for GAMMA checks", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Ignore deleting Service, this can happen when foregroundDeletion is enabled
	// The reconciliation loop will automatically kick off for related GAMMA Service resources.
	if originalSvc.GetDeletionTimestamp() != nil {
		scopedLog.InfoContext(ctx, "Service is being deleted, doing nothing")
		return controllerruntime.Success()
	}

	svc := originalSvc.DeepCopy()

	var gammaService bool

	// Step 2: Gather all required information for the ingestion model

	httpRouteList := &gatewayv1.HTTPRouteList{}
	if err := r.Client.List(ctx, httpRouteList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.GammaHTTPRouteParentRefsIndex, client.ObjectKeyFromObject(svc).String()),
	}); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list HTTPRoutes", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	if len(httpRouteList.Items) != 0 {
		scopedLog.InfoContext(ctx, "Referencing HTTPRoute found, GAMMA Service")
		gammaService = true
	}

	grpcRouteList := &gatewayv1.GRPCRouteList{}
	if err := r.Client.List(ctx, grpcRouteList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.GammaGRPCRouteParentRefsIndex, client.ObjectKeyFromObject(svc).String()),
	}); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list GRPCRoutes", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	if len(grpcRouteList.Items) != 0 {
		scopedLog.InfoContext(ctx, "GRPCRoute found, GAMMA Service")
		gammaService = true
	}

	if !gammaService {
		return controllerruntime.Success()
	}

	scopedLog.DebugContext(ctx, "Service exists and is a GAMMA Service", relevantHTTPRoutes, len(httpRouteList.Items))

	// TODO(tam): Only list the services / ServiceImports used by accepted Routes
	servicesList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, servicesList); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list Services", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list ReferenceGrants", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Run the HTTPRoute route checks here and update the status accordingly.
	if err := r.setHTTPRouteStatuses(scopedLog, ctx, originalSvc, httpRouteList, grants); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update HTTPRoute Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Run the GRPCRoute route checks here and update the status accordingly.
	if err := r.setGRPCRouteStatuses(scopedLog, ctx, originalSvc, grpcRouteList, grants); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update GRPCRoute Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// TODO(youngnick): GammaHTTPRoutes needs to be updated now that we have a source Service.
	httpListeners := ingestion.GammaHTTPRoutes(r.logger, ingestion.GammaInput{
		HTTPRoutes: httpRouteList.Items,
		GRPCRoutes: grpcRouteList.Items,
		Services:   servicesList.Items,

		ReferenceGrants: grants.Items,
	})

	setGammaServiceAccepted(svc, true, "Gamma Service has HTTPRoutes attached", CiliumGammaReasonAccepted)

	cec, _, cep, err := r.translator.Translate(&model.Model{HTTP: httpListeners})
	if err != nil {
		scopedLog.ErrorContext(ctx, "Unable to translate resources", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, originalSvc, svc)
	}

	if err = r.ensureEnvoyConfig(ctx, cec); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to ensure CiliumEnvoyConfig", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, originalSvc, svc)
	}

	if err = r.ensureEndpointSlice(ctx, cep); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to ensure Endpoints", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, originalSvc, svc)
	}

	setGammaServiceProgrammed(svc, true, "Gamma Service has been programmed", CiliumGammaReasonProgrammed)
	if err := r.updateStatus(ctx, originalSvc, svc); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update Gamma Service status: %w", err))
	}

	scopedLog.InfoContext(ctx, "Successfully reconciled GAMMA Service")
	return controllerruntime.Success()
}

func (r *gammaReconciler) setHTTPRouteStatuses(gammaLogger *slog.Logger, ctx context.Context, gammaService *corev1.Service, httpRoutes *gatewayv1.HTTPRouteList, grants *gatewayv1beta1.ReferenceGrantList) error {
	gammaLogger.DebugContext(ctx, "Updating HTTPRoute statuses for GAMMA Service", numRoutes, len(httpRoutes.Items))
	for _, original := range httpRoutes.Items {

		hr := original.DeepCopy()

		hrName := types.NamespacedName{
			Name:      hr.Name,
			Namespace: hr.Namespace,
		}
		// input for the validators
		i := &routechecks.HTTPRouteInput{
			Ctx:       ctx,
			Logger:    gammaLogger.With(httpRoute, hrName),
			Client:    r.Client,
			Grants:    grants,
			HTTPRoute: hr,
		}

		// Route validators
		for _, parent := range hr.Spec.ParentRefs {

			if !helpers.IsGammaServiceEqual(parent, gammaService, hr.Namespace) {
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
					return r.handleHTTPRouteReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply parentRef check: %w", err), &original, hr)
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
					return r.handleHTTPRouteReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply route rule check: %w", err), &original, hr)
				}

				if !continueCheck {
					break
				}
			}

		}

		if err := r.updateHTTPRouteStatus(ctx, &original, hr); err != nil {
			return fmt.Errorf("failed to update HTTPRoute status: %w", err)
		}
	}

	return nil
}

func (r *gammaReconciler) setGRPCRouteStatuses(gammaLogger *slog.Logger, ctx context.Context, gammaService *corev1.Service, grpcRoutes *gatewayv1.GRPCRouteList, grants *gatewayv1beta1.ReferenceGrantList) error {
	gammaLogger.DebugContext(ctx, "Updating GRPCRoute statuses for GAMMA Service", numRoutes, len(grpcRoutes.Items))
	for _, original := range grpcRoutes.Items {

		grpc := original.DeepCopy()

		grpcName := types.NamespacedName{
			Name:      grpc.Name,
			Namespace: grpc.Namespace,
		}
		// input for the validators
		i := &routechecks.GRPCRouteInput{
			Ctx:       ctx,
			Logger:    gammaLogger.With(grpcRoute, grpcName),
			Client:    r.Client,
			Grants:    grants,
			GRPCRoute: grpc,
		}

		// Route validators
		for _, parent := range grpc.Spec.ParentRefs {

			if !helpers.IsGammaServiceEqual(parent, gammaService, grpc.Namespace) {
				continue
			}

			// set acceptance to okay, this wil be overwritten in checks if needed
			i.SetParentCondition(parent, metav1.Condition{
				Type:    string(gatewayv1.RouteConditionAccepted),
				Status:  metav1.ConditionTrue,
				Reason:  string(gatewayv1.RouteReasonAccepted),
				Message: "Accepted GRPCRoute",
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
					return r.handleGRPCRouteReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply parentRef check: %w", err), &original, grpc)
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
					return r.handleGRPCRouteReconcileErrorWithStatus(ctx, fmt.Errorf("failed to apply route rule check: %w", err), &original, grpc)
				}

				if !continueCheck {
					break
				}
			}

		}

		if err := r.updateGRPCRouteStatus(ctx, &original, grpc); err != nil {
			return fmt.Errorf("failed to update GRPCRoute status: %w", err)
		}
	}

	return nil
}

func (r *gammaReconciler) ensureEndpointSlice(ctx context.Context, desired *discoveryv1.EndpointSlice) error {
	ep := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, ep, func() error {
		ep.Endpoints = desired.Endpoints
		ep.Ports = desired.Ports
		ep.OwnerReferences = desired.OwnerReferences
		setMergedLabelsAndAnnotations(ep, desired)
		return nil
	})
	return err
}

func (r *gammaReconciler) ensureEnvoyConfig(ctx context.Context, desired *ciliumv2.CiliumEnvoyConfig) error {
	cec := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, cec, func() error {
		cec.Spec = desired.Spec
		setMergedLabelsAndAnnotations(cec, desired)
		return nil
	})
	return err
}

func (r *gammaReconciler) updateStatus(ctx context.Context, original *corev1.Service, new *corev1.Service) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}

func (r *gammaReconciler) handleReconcileErrorWithStatus(ctx context.Context, reconcileErr error, original *corev1.Service, modified *corev1.Service) (ctrl.Result, error) {
	if err := r.updateStatus(ctx, original, modified); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err))
	}

	return controllerruntime.Fail(reconcileErr)
}

func (r *gammaReconciler) updateHTTPRouteStatus(ctx context.Context, original *gatewayv1.HTTPRoute, new *gatewayv1.HTTPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	r.logger.DebugContext(ctx, "Updating HTTRRoute status", httpRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return r.Client.Status().Update(ctx, new)
}

func (r *gammaReconciler) handleHTTPRouteReconcileErrorWithStatus(ctx context.Context, reconcileErr error, original *gatewayv1.HTTPRoute, modified *gatewayv1.HTTPRoute) error {
	if err := r.updateHTTPRouteStatus(ctx, original, modified); err != nil {
		return fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err)
	}
	return nil
}

func (r *gammaReconciler) updateGRPCRouteStatus(ctx context.Context, original *gatewayv1.GRPCRoute, new *gatewayv1.GRPCRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	r.logger.DebugContext(ctx, "Updating GRPCRoute status", grpcRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return r.Client.Status().Update(ctx, new)
}

func (r *gammaReconciler) handleGRPCRouteReconcileErrorWithStatus(ctx context.Context, reconcileErr error, original *gatewayv1.GRPCRoute, modified *gatewayv1.GRPCRoute) error {
	if err := r.updateGRPCRouteStatus(ctx, original, modified); err != nil {
		return fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err)
	}
	return nil
}
