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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// gammaReconciler reconciles a Gateway object
type gammaReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	translator translation.Translator

	logger                    *slog.Logger
	controllerName            string
	enableExtensionRefFilters bool
}

func newGammaReconciler(mgr ctrl.Manager, translator translation.Translator, logger *slog.Logger, controllerName string, enableExtensionRefFilters bool) *gammaReconciler {
	return &gammaReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		translator: translator,
		logger: logger.With(
			logfields.Controller, gamma,
		),
		controllerName:            controllerName,
		enableExtensionRefFilters: enableExtensionRefFilters,
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

	if r.enableExtensionRefFilters {
		gammaBuilder = gammaBuilder.Watches(
			&v2alpha1.CiliumEnvoyExtProcFilter{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueAllGammaServices()),
		)
	}

	return gammaBuilder.Complete(r)
}

func (r *gammaReconciler) enqueueAllGammaServices() handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		svcList := &corev1.ServiceList{}
		if err := r.Client.List(ctx, svcList); err != nil {
			return nil
		}
		var requests []reconcile.Request
		for _, svc := range svcList.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(&svc),
			})
		}
		return requests
	}
}
