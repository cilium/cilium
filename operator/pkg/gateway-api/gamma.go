// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// gammaReconciler reconciles a Gateway object
type gammaReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	translator translation.Translator

	logger *slog.Logger
}

func newGammaReconciler(mgr ctrl.Manager, translator translation.Translator, logger *slog.Logger) *gammaReconciler {
	return &gammaReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		translator: translator,
		logger: logger.With(
			logfields.Controller, gamma,
		),
	}
}

// SetupWithManager sets up the controller with the Manager.
// The reconciler will be triggered by Gateway, or any cilium-managed GatewayClass events
func (r *gammaReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// This creates an index on HTTPRoutes, adding an field called `gammaParents` which lists
	// all the GAMMA parents of that HTTPRoute.
	// This is then be used by the Service reconciler to only retrieve any HTTPRoutes that have that specific
	// Service as a parent.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, indexers.GammaHTTPRouteParentRefsIndex, indexers.IndexHTTPRouteByGammaService); err != nil {
		return err
	}

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GRPCRoute{}, indexers.GammaGRPCRouteParentRefsIndex, indexers.IndexGRPCRouteByGammaService); err != nil {
		return err
	}

	gammaBuilder := ctrl.NewControllerManagedBy(mgr).
		Named("gammaService").
		// Watch its own resource
		For(&corev1.Service{}).
		// Watch HTTPRoute linked to Service
		Watches(&gatewayv1.HTTPRoute{}, watchhandlers.EnqueueRequestForGAMMAHTTPRoute(r.Client, r.logger)).
		// Watch GRPCRoute linked to Service
		Watches(&gatewayv1.GRPCRoute{}, watchhandlers.EnqueueRequestForGAMMAGRPCRoute(r.Client, r.logger)).
		// Watch for changes to Reference Grants
		Watches(&gatewayv1.ReferenceGrant{}, watchhandlers.EnqueueRequestForGAMMAReferenceGrant(r.Client, r.logger)).
		// Watch created and owned resources
		Owns(&ciliumv2.CiliumEnvoyConfig{})

	return gammaBuilder.Complete(r)
}
