// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
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
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, gammaParentRefsIndex, getGammaHTTPRouteParentIndexFunc(r.logger)); err != nil {
		return err
	}

	gammaBuilder := ctrl.NewControllerManagedBy(mgr).
		Named("gammaService").
		// Watch its own resource
		For(&corev1.Service{}).
		// Watch HTTPRoute linked to Gateway
		Watches(&gatewayv1.HTTPRoute{}, r.enqueueRequestForOwningHTTPRoute(r.logger)).
		// Watch for changes to Reference Grants
		Watches(&gatewayv1beta1.ReferenceGrant{}, r.enqueueRequestForReferenceGrant()).
		// Watch created and owned resources
		Owns(&ciliumv2.CiliumEnvoyConfig{})

	return gammaBuilder.Complete(r)
}

// enqueueRequestForOwningHTTPRoute returns an event handler for any changes with HTTP Routes
// belonging to the given Service
func (r *gammaReconciler) enqueueRequestForOwningHTTPRoute(logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		hr, ok := a.(*gatewayv1.HTTPRoute)
		if !ok {
			return nil
		}

		return getGammaReconcileRequestsForRoute(ctx, r.Client, a, hr.Spec.CommonRouteSpec, logger)
	})
}

func (r *gammaReconciler) enqueueRequestForReferenceGrant() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueAll())
}

func (r *gammaReconciler) enqueueAll() handler.MapFunc {
	// TODO(youngnick): This approach will scale poorly with large numbers of
	// Services; each ReferenceGrant update will trigger reconciliation of _all_ Services.
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.logger.With(
			logfields.Controller, gamma,
			logfields.Resource, client.ObjectKeyFromObject(o),
		)
		list := &corev1.ServiceList{}

		if err := r.Client.List(ctx, list, &client.ListOptions{}); err != nil {
			scopedLog.Error("Failed to list Service", logfields.Error, err)
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(list.Items))
		for _, item := range list.Items {
			svc := client.ObjectKey{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: svc,
			})
			scopedLog.Info("Enqueued Service for resource", gamma, svc)
		}
		return requests
	}
}

func getGammaHTTPRouteParentIndexFunc(logger *slog.Logger) func(rawObj client.Object) []string {
	return func(rawObj client.Object) []string {
		hr, ok := rawObj.(*gatewayv1.HTTPRoute)
		if !ok {
			return []string{}
		}
		scopedLog := logger.With(namespacedName, types.NamespacedName{
			Namespace: hr.Namespace,
			Name:      hr.Name,
		})
		gammaParentRefs := []string{}

		for _, parent := range hr.Spec.ParentRefs {
			if helpers.IsGammaService(parent) {
				ns := helpers.NamespaceDerefOr(parent.Namespace, hr.Namespace)
				gammaParentRefs = append(gammaParentRefs,
					types.NamespacedName{
						Namespace: ns,
						Name:      string(parent.Name),
					}.String())
				scopedLog.Debug("Added at least one GAMMA Service to GAMMA index", validGammaServices, gammaParentRefs)
			}
		}

		return gammaParentRefs
	}
}

// getGammaReconcileRequestsForRoute returns a list of GAMMA services to be reconciled based on the supplied HTTPRoute.
func getGammaReconcileRequestsForRoute(ctx context.Context, c client.Client, object metav1.Object, route gatewayv1.CommonRouteSpec, logger *slog.Logger) []reconcile.Request {
	var reqs []reconcile.Request

	scopedLog := logger.With(
		logfields.Controller, gamma,
		logfields.Resource, types.NamespacedName{
			Namespace: object.GetNamespace(),
			Name:      object.GetName(),
		},
	)

	for _, parent := range route.ParentRefs {
		if helpers.IsGateway(parent) {
			continue
		}

		ns := helpers.NamespaceDerefOr(parent.Namespace, object.GetNamespace())

		s := &corev1.Service{}
		if err := c.Get(ctx, types.NamespacedName{
			Namespace: ns,
			Name:      string(parent.Name),
		}, s); err != nil {
			if !k8serrors.IsNotFound(err) {
				scopedLog.Error("Failed to get Gamma Service", logfields.Error, err)
			}
			continue
		}

		if !isValidGammaService(s) {
			scopedLog.Warn("Service referenced as GAMMA parent is not valid")
			continue
		}

		scopedLog.Info("Enqueued GAMMA Service for Route",
			logfields.K8sNamespace, ns,
			logfields.Resource, parent.Name,
			logfields.Route, object.GetName())

		reqs = append(reqs, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: ns,
				Name:      string(parent.Name),
			},
		})
	}

	return reqs
}

func isValidGammaService(svc *corev1.Service) bool {
	if svc.Spec.Type == corev1.ServiceTypeClusterIP {
		return true
	}

	return false
}
