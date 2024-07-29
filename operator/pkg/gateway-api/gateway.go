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
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	owningGatewayLabel = "io.cilium.gateway/owning-gateway"

	lastTransitionTime = "LastTransitionTime"
)

// gatewayReconciler reconciles a Gateway object
type gatewayReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	translator translation.Translator

	logger *slog.Logger
}

func newGatewayReconciler(mgr ctrl.Manager, translator translation.Translator, logger *slog.Logger) *gatewayReconciler {
	return &gatewayReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		translator: translator,
		logger:     logger,
	}
}

// SetupWithManager sets up the controller with the Manager.
// The reconciler will be triggered by Gateway, or any cilium-managed GatewayClass events
func (r *gatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	hasMatchingControllerFn := hasMatchingController(context.Background(), r.Client, controllerName, r.logger)
	return ctrl.NewControllerManagedBy(mgr).
		// Watch its own resource
		For(&gatewayv1.Gateway{},
			builder.WithPredicates(predicate.NewPredicateFuncs(hasMatchingControllerFn))).
		// Watch GatewayClass resources, which are linked to Gateway
		Watches(&gatewayv1.GatewayClass{},
			r.enqueueRequestForOwningGatewayClass(),
			builder.WithPredicates(predicate.NewPredicateFuncs(matchesControllerName(controllerName)))).
		// Watch related LB service for status
		Watches(&corev1.Service{},
			r.enqueueRequestForOwningResource(),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(object client.Object) bool {
				_, found := object.GetLabels()[owningGatewayLabel]
				return found
			}))).
		// Watch HTTP Route status changes, there is one assumption that any change in spec will
		// always update status always at least for observedGeneration value.
		Watches(&gatewayv1.HTTPRoute{},
			r.enqueueRequestForOwningHTTPRoute(r.logger),
			builder.WithPredicates(onlyStatusChanged())).
		// Watch TLS Route status changes, there is one assumption that any change in spec will
		// always update status always at least for observedGeneration value.
		Watches(&gatewayv1alpha2.TLSRoute{},
			r.enqueueRequestForOwningTLSRoute(r.logger),
			builder.WithPredicates(onlyStatusChanged())).
		// Watch GRPCRoute status changes, there is one assumption that any change in spec will
		// always update status always at least for observedGeneration value.
		Watches(&gatewayv1.GRPCRoute{},
			r.enqueueRequestForOwningGRPCRoute(),
			builder.WithPredicates(onlyStatusChanged())).
		// Watch related secrets used to configure TLS
		Watches(&corev1.Secret{},
			r.enqueueRequestForTLSSecret(),
			builder.WithPredicates(predicate.NewPredicateFuncs(r.usedInGateway))).
		// Watch related namespace in allowed namespaces
		Watches(&corev1.Namespace{},
			r.enqueueRequestForAllowedNamespace()).
		// Watch for changes to Reference Grants
		Watches(&gatewayv1beta1.ReferenceGrant{}, r.enqueueRequestForReferenceGrant()).
		// Watch created and owned resources
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Endpoints{}).
		Complete(r)
}

// enqueueRequestForOwningGatewayClass returns an event handler for all Gateway objects
// belonging to the given GatewayClass.
func (r *gatewayReconciler) enqueueRequestForOwningGatewayClass() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		scopedLog := r.logger.With(logfields.Controller, gateway, logfields.Resource, a.GetName())
		var reqs []reconcile.Request
		gwList := &gatewayv1.GatewayList{}
		if err := r.Client.List(ctx, gwList); err != nil {
			scopedLog.Error("Unable to list Gateways")
			return nil
		}

		for _, gw := range gwList.Items {
			if gw.Spec.GatewayClassName != gatewayv1.ObjectName(a.GetName()) {
				continue
			}
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: gw.Namespace,
					Name:      gw.Name,
				},
			}
			reqs = append(reqs, req)
			scopedLog.Info("Queueing gateway", logfields.K8sNamespace, gw.GetNamespace(), logfields.Resource, gw.GetName())
		}
		return reqs
	})
}

// enqueueRequestForOwningResource returns an event handler for all Gateway objects having
// owningGatewayLabel
func (r *gatewayReconciler) enqueueRequestForOwningResource() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		scopedLog := r.logger.With(logfields.Controller, "gateway", logfields.Resource, a.GetName())

		key, found := a.GetLabels()[owningGatewayLabel]
		if !found {
			return nil
		}

		scopedLog.Info("Enqueued gateway for owning service",
			logfields.K8sNamespace, a.GetNamespace(),
			logfields.Resource, a.GetName(),
			"gateway", key,
		)

		return []reconcile.Request{
			{
				NamespacedName: types.NamespacedName{
					Namespace: a.GetNamespace(),
					Name:      key,
				},
			},
		}
	})
}

// enqueueRequestForOwningHTTPRoute returns an event handler for any changes with HTTP Routes
// belonging to the given Gateway
func (r *gatewayReconciler) enqueueRequestForOwningHTTPRoute(logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		hr, ok := a.(*gatewayv1.HTTPRoute)
		if !ok {
			return nil
		}

		return getReconcileRequestsForRoute(context.Background(), r.Client, a, hr.Spec.CommonRouteSpec, logger)
	})
}

// enqueueRequestForOwningTLSRoute returns an event handler for any changes with TLS Routes
// belonging to the given Gateway
func (r *gatewayReconciler) enqueueRequestForOwningTLSRoute(logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		hr, ok := a.(*gatewayv1alpha2.TLSRoute)
		if !ok {
			return nil
		}

		return getReconcileRequestsForRoute(context.Background(), r.Client, a, hr.Spec.CommonRouteSpec, logger)
	})
}

// enqueueRequestForOwningGRPCRoute returns an event handler for any changes with GRPC Routes
// belonging to the given Gateway
func (r *gatewayReconciler) enqueueRequestForOwningGRPCRoute() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		gr, ok := a.(*gatewayv1.GRPCRoute)
		if !ok {
			return nil
		}

		return getReconcileRequestsForRoute(ctx, r.Client, a, gr.Spec.CommonRouteSpec, r.logger)
	})
}

func getReconcileRequestsForRoute(ctx context.Context, c client.Client, object metav1.Object, route gatewayv1.CommonRouteSpec, logger *slog.Logger) []reconcile.Request {
	var reqs []reconcile.Request

	scopedLog := logger.With(
		logfields.Controller, gateway,
		logfields.Resource, types.NamespacedName{
			Namespace: object.GetNamespace(),
			Name:      object.GetName(),
		},
	)

	for _, parent := range route.ParentRefs {
		if !helpers.IsGateway(parent) {
			continue
		}

		ns := helpers.NamespaceDerefOr(parent.Namespace, object.GetNamespace())

		gw := &gatewayv1.Gateway{}
		if err := c.Get(ctx, types.NamespacedName{
			Namespace: ns,
			Name:      string(parent.Name),
		}, gw); err != nil {
			if !k8serrors.IsNotFound(err) {
				scopedLog.Error("Failed to get Gateway", logfields.Error, err)
			}
			continue
		}

		if !hasMatchingController(ctx, c, controllerName, logger)(gw) {
			scopedLog.Debug("Gateway does not have matching controller, skipping")
			continue
		}

		scopedLog.Info("Enqueued gateway for Route",
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

// enqueueRequestForOwningTLSCertificate returns an event handler for any changes with TLS secrets
func (r *gatewayReconciler) enqueueRequestForTLSSecret() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		gateways := getGatewaysForSecret(ctx, r.Client, a, r.logger)
		reqs := make([]reconcile.Request, 0, len(gateways))
		for _, gw := range gateways {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: gw.GetNamespace(),
					Name:      gw.GetName(),
				},
			})
		}
		return reqs
	})
}

// enqueueRequestForAllowedNamespace returns an event handler for any changes
// with allowed namespaces
func (r *gatewayReconciler) enqueueRequestForAllowedNamespace() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, ns client.Object) []reconcile.Request {
		gateways := getGatewaysForNamespace(ctx, r.Client, ns, r.logger)
		reqs := make([]reconcile.Request, 0, len(gateways))
		for _, gw := range gateways {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: gw,
			})
		}
		return reqs
	})
}

func (r *gatewayReconciler) usedInGateway(obj client.Object) bool {
	return len(getGatewaysForSecret(context.Background(), r.Client, obj, r.logger)) > 0
}

func (r *gatewayReconciler) enqueueRequestForReferenceGrant() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueAll())
}

func (r *gatewayReconciler) enqueueAll() handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.logger.With(logfields.Controller, gateway, logfields.Resource, client.ObjectKeyFromObject(o))
		list := &gatewayv1.GatewayList{}

		if err := r.Client.List(ctx, list, &client.ListOptions{}); err != nil {
			scopedLog.Error("Failed to list Gateway", logfields.Error, err)
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(list.Items))
		for _, item := range list.Items {
			gw := client.ObjectKey{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: gw,
			})
			scopedLog.Info("Enqueued Gateway for resource", gateway, gw)
		}
		return requests
	}
}
