// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

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
	gwc := &gatewayv1.GatewayClass{}
	if err := r.Client.Get(ctx, req.NamespacedName, gwc); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		return controllerruntime.Fail(err)
	}

	// Ignore deleted GatewayClass, this can happen when foregroundDeletion is enabled
	// The reconciliation loop will automatically kick off for related Gateway resources.
	if gwc.GetDeletionTimestamp() != nil {
		return controllerruntime.Success()
	}

	// TODO(tam): Support spec.ParametersRef later for different use cases
	// Right now, we will still support multiple gateway class, but no support for parameters.
	// Hence, just set gateway class Accepted condition to true blindly.
	setGatewayClassAccepted(gwc, true)

	// List of features supported by Cilium.
	// The same is used in GHA CI .github/workflows/conformance-gateway-api.yaml
	gwc.Status.SupportedFeatures = []gatewayv1.SupportedFeature{
		"Gateway",
		//"GatewayPort8080",
		//"GatewayStaticAddresses",
		"HTTPRoute",
		"HTTPRouteDestinationPortMatching",
		"HTTPRouteHostRewrite",
		"HTTPRouteMethodMatching",
		"HTTPRoutePathRedirect",
		"HTTPRoutePathRewrite",
		"HTTPRoutePortRedirect",
		"HTTPRouteQueryParamMatching",
		"HTTPRouteRequestMirror",
		"HTTPRouteRequestMultipleMirrors",
		"HTTPRouteResponseHeaderModification",
		"HTTPRouteSchemeRedirect",
		//"Mesh",
		"ReferenceGrant",
		"TLSRoute",
	}

	if err := r.Client.Status().Update(ctx, gwc); err != nil {
		scopedLog.WithError(err).Error("Failed to update GatewayClass status")
		return controllerruntime.Fail(err)
	}
	scopedLog.Info("Successfully reconciled GatewayClass")
	return controllerruntime.Success()
}
