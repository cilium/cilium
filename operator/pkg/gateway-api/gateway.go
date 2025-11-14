// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// Deprecated: owningGatewayLabel will be removed later in favour of gatewayNameLabel
	owningGatewayLabel = "io.cilium.gateway/owning-gateway"

	lastTransitionTime = "LastTransitionTime"
)

// gatewayReconciler reconciles a Gateway object
type gatewayReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	translator translation.Translator

	logger        *slog.Logger
	installedCRDs []schema.GroupVersionKind
}

func newGatewayReconciler(mgr ctrl.Manager, translator translation.Translator, logger *slog.Logger, installedCRDs []schema.GroupVersionKind) *gatewayReconciler {
	scopedLog := logger.With(logfields.Controller, gateway)

	return &gatewayReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		translator:    translator,
		logger:        scopedLog,
		installedCRDs: installedCRDs,
	}
}

// SetupWithManager sets up the controller with the Manager.
// The reconciler will be triggered by Gateway, or any cilium-managed GatewayClass events
func (r *gatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Determine which optional CRDs are enabled
	var tlsRouteEnabled, serviceImportEnabled bool

	for _, gvk := range r.installedCRDs {
		switch gvk.Kind {
		case helpers.TLSRouteKind:
			tlsRouteEnabled = true
		case helpers.ServiceImportKind:
			serviceImportEnabled = true
		}
	}

	// Add field indexes for HTTPRoutes
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		backendServiceHTTPRouteIndex: indexers.GenerateIndexerHTTPRouteByBackendService(r.Client, r.logger),
		gatewayHTTPRouteIndex:        indexers.IndexHTTPRouteByGateway,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	// Only index HTTPRoute by ServiceImport if ServiceImport is enabled
	if serviceImportEnabled {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, backendServiceImportHTTPRouteIndex, indexers.IndexHTTPRouteByBackendServiceImport); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", backendServiceImportHTTPRouteIndex, err)
		}
	}

	// Index Gateways by implementation (ie `cilium`)
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.Gateway{}, implementationGatewayIndex, indexers.GenerateIndexerGatewayByImplementation(r.Client, controllerName)); err != nil {
		return fmt.Errorf("failed to setup field indexer %q: %w", implementationGatewayIndex, err)
	}

	// Add indexes for TLSRoutes
	if tlsRouteEnabled {
		for indexName, indexerFunc := range map[string]client.IndexerFunc{
			backendServiceTLSRouteIndex: indexers.GenerateIndexerTLSRoutebyBackendService(r.Client, r.logger),
			gatewayTLSRouteIndex:        indexers.IndexTLSRouteByGateway,
		} {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1alpha2.TLSRoute{}, indexName, indexerFunc); err != nil {
				return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
			}
		}
	}

	// Add field indexes for GRPCRoutes
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		backendServiceGRPCRouteIndex: indexers.GenerateIndexerGRPCRoutebyBackendService(r.Client, r.logger),
		gatewayGRPCRouteIndex:        indexers.IndexGRPCRouteByGateway,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GRPCRoute{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	// IndexBackendTLSPolicies by referenced ConfigMaps
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.BackendTLSPolicy{}, backendTLSPolicyConfigMapIndex, indexers.IndexBTLSPolicyByConfigMap); err != nil {
		return fmt.Errorf("failed to setup field indexer %q: %w", backendTLSPolicyConfigMapIndex, err)
	}

	hasMatchingControllerFn := hasMatchingController(context.Background(), r.Client, controllerName, r.logger)
	gatewayBuilder := ctrl.NewControllerManagedBy(mgr).
		// Watch its own resource
		For(&gatewayv1.Gateway{},
			builder.WithPredicates(predicate.NewPredicateFuncs(hasMatchingControllerFn))).
		// Watch GatewayClass resources, which are linked to Gateway
		Watches(&gatewayv1.GatewayClass{},
			r.enqueueRequestForOwningGatewayClass(),
			builder.WithPredicates(predicate.NewPredicateFuncs(matchesControllerName(controllerName)))).
		// Watch related backend Service for status
		// LB Services are handled by the Owns call later.
		Watches(&corev1.Service{}, r.enqueueRequestForBackendService()).
		// Watch HTTPRoute linked to Gateway
		Watches(&gatewayv1.HTTPRoute{}, r.enqueueRequestForOwningHTTPRoute(r.logger)).
		// Watch GRPCRoute linked to Gateway
		Watches(&gatewayv1.GRPCRoute{}, r.enqueueRequestForOwningGRPCRoute()).
		// Watch related secrets used to configure TLS
		Watches(&corev1.Secret{},
			r.enqueueRequestForTLSSecret(),
			builder.WithPredicates(predicate.NewPredicateFuncs(r.usedInGateway))).
		// Watch related namespace in allowed namespaces
		Watches(&corev1.Namespace{},
			r.enqueueRequestForAllowedNamespace()).
		// Watch for changes to Reference Grants
		Watches(&gatewayv1beta1.ReferenceGrant{}, r.enqueueRequestForReferenceGrant()).
		// Watcgh for changes to BackendTLSPolicy
		Watches(&gatewayv1.BackendTLSPolicy{}, r.enqueueRequestForBackendTLSPolicy()).
		Watches(&corev1.ConfigMap{}, r.enqueueRequestForBackendTLSPolicyConfigMap()).
		// Watch created and owned resources
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		Owns(&corev1.Service{}).
		Owns(&discoveryv1.EndpointSlice{})

	if tlsRouteEnabled {
		// Watch TLSRoute linked to Gateway
		gatewayBuilder = gatewayBuilder.Watches(&gatewayv1alpha2.TLSRoute{}, r.enqueueRequestForOwningTLSRoute(r.logger))
	}

	if serviceImportEnabled {
		// Watch for changes to Backend Service Imports
		gatewayBuilder = gatewayBuilder.Watches(&mcsapiv1alpha1.ServiceImport{}, r.enqueueRequestForBackendServiceImport())
	}

	return gatewayBuilder.Complete(r)
}

// enqueueRequestForOwningGatewayClass returns an event handler that, when given a GatewayClass,
// returns reconcile.Requests for all Gateway objects belonging to the given GatewayClass.
func (r *gatewayReconciler) enqueueRequestForOwningGatewayClass() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		scopedLog := r.logger.With(
			logfields.Resource, client.ObjectKeyFromObject(a).String(),
		)
		var reqs []reconcile.Request
		gwList := &gatewayv1.GatewayList{}
		if err := r.Client.List(ctx, gwList); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list Gateways")
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
			scopedLog.InfoContext(ctx,
				"Queueing gateway",
				logfields.K8sNamespace, gw.GetNamespace(),
				gateway, gw.GetName(),
			)
		}
		return reqs
	})
}

// enqueueRequestForOwningHTTPRoute returns an event handler that, when passed a HTTPRoute, returns reconcile.Requests
// for all Cilium-relevant Gateways associated with that HTTPRoute.
func (r *gatewayReconciler) enqueueRequestForOwningHTTPRoute(logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		hr, ok := a.(*gatewayv1.HTTPRoute)
		if !ok {
			return nil
		}

		return getGatewayReconcileRequestsForRoute(context.Background(), r.Client, a, hr.Spec.CommonRouteSpec, logger)
	})
}

// enqueueRequestForOwningTLSRoute returns an event handler that, when passed a TLSRoute, returns reconcile.Requests
// for all Cilium-relevant Gateways associated with that TLSRoute.
func (r *gatewayReconciler) enqueueRequestForOwningTLSRoute(logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		hr, ok := a.(*gatewayv1alpha2.TLSRoute)
		if !ok {
			return nil
		}

		return getGatewayReconcileRequestsForRoute(context.Background(), r.Client, a, hr.Spec.CommonRouteSpec, logger)
	})
}

// enqueueRequestForOwningGRPCRoute returns an event handler that, when passed a GRPCRoute, returns reconcile.Requests
// for any Cilium-relevant Gateways associated with that GRPCRoute.
func (r *gatewayReconciler) enqueueRequestForOwningGRPCRoute() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		gr, ok := a.(*gatewayv1.GRPCRoute)
		if !ok {
			return nil
		}

		return getGatewayReconcileRequestsForRoute(ctx, r.Client, a, gr.Spec.CommonRouteSpec, r.logger)
	})
}

// enqueueRequestForBackendService returns an event handler that, when passed a Service, returns reconcile.Requests
// for all Cilium-relevant Gateways where that Service is used as a backend for a HTTPRoute that is attached to that Gateway.
func (r *gatewayReconciler) enqueueRequestForBackendService() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		_, ok := o.(*corev1.Service)
		if !ok {
			return nil
		}

		scopedLog := r.logger.With(logfields.LogSubsys, "queue-gw-from-backend-svc")

		// Make a set to hold all reconcile requests
		reconcileRequests := make(map[reconcile.Request]struct{})

		// Then, fetch all HTTPRoutes that reference this service, using the backendServiceIndex
		hrList := &gatewayv1.HTTPRouteList{}

		if err := r.Client.List(ctx, hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(backendServiceHTTPRouteIndex, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related HTTPRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		// Then, fetch all TLSRoutes that reference this service, using the backendServiceIndex
		tlsrList := &gatewayv1alpha2.TLSRouteList{}

		if err := r.Client.List(ctx, tlsrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(backendServiceTLSRouteIndex, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.Error("Failed to get related HTTPRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		grpcRouteList := &gatewayv1.GRPCRouteList{}
		if err := r.Client.List(ctx, grpcRouteList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(backendServiceGRPCRouteIndex, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list GRPCRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		// Fetch all the Cilium-relevant Gateways using the implementationGatewayIndex.
		gwList := &gatewayv1.GatewayList{}
		if err := r.Client.List(ctx, gwList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(implementationGatewayIndex, "cilium"),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		// Build a set of all Cilium Gateway full names.
		// This makes sure we only add a reconcile.Request once for each Gateway.
		allCiliumGatewaysSet := make(map[string]struct{})

		for _, gw := range gwList.Items {
			gwFullName := types.NamespacedName{
				Name:      gw.GetName(),
				Namespace: gw.GetNamespace(),
			}
			allCiliumGatewaysSet[gwFullName.String()] = struct{}{}
		}

		// iterate through the HTTPRoutes, update reconcileRequests for each Gateway that is relevant.
		for _, hr := range hrList.Items {
			updateReconcileRequestsForParentRefs(hr.Spec.ParentRefs, hr.Namespace, allCiliumGatewaysSet, reconcileRequests)
		}

		// iterate through the TLSRoutes, update reconcileRequests for each Gateway that is relevant.
		for _, tlsr := range tlsrList.Items {
			updateReconcileRequestsForParentRefs(tlsr.Spec.ParentRefs, tlsr.Namespace, allCiliumGatewaysSet, reconcileRequests)
		}

		// iterate through the TLSRoutes, update reconcileRequests for each Gateway that is relevant.
		for _, grpcr := range grpcRouteList.Items {
			updateReconcileRequestsForParentRefs(grpcr.Spec.ParentRefs, grpcr.Namespace, allCiliumGatewaysSet, reconcileRequests)
		}

		// return the keys of the set, since that's the actual reconcile.Requests.
		return slices.Collect(maps.Keys(reconcileRequests))
	})
}

// enqueueRequestForBackendTLSPolicy returns an event handler that, when passed a BackendTLSPolicy, returns reconcile.Requests
// for all Cilium-relevant Gateways where that BackendTLSPolicy references a Service that is used as a backend for a
// Route that is attached to that Gateway.
func (r *gatewayReconciler) enqueueRequestForBackendTLSPolicy() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.logger.With(logfields.LogSubsys, "queue-gw-from-backendtlspolicy")

		reconcileRequests := make(map[reconcile.Request]struct{})
		btlsp, ok := o.(*gatewayv1.BackendTLSPolicy)
		if !ok {
			return nil
		}

		ns := o.GetNamespace()
		serviceRefs := []string{}
		// First, we collect Service references from the TargetRefs
		for _, target := range btlsp.Spec.TargetRefs {
			if helpers.IsServiceTargetRef(target) {
				serviceRefs = append(serviceRefs, ns+"/"+string(target.Name))
			}
		}

		httpRoutes := []gatewayv1.HTTPRoute{}

		for _, svcName := range serviceRefs {
			// Then, fetch all HTTPRoutes that reference this service, using the backendServiceIndex
			hrList := &gatewayv1.HTTPRouteList{}

			if err := r.Client.List(ctx, hrList, &client.ListOptions{
				FieldSelector: fields.OneTermEqualSelector(backendServiceHTTPRouteIndex, svcName),
			}); err != nil {
				scopedLog.ErrorContext(ctx, "Failed to get related HTTPRoutes", logfields.Error, err)
				return []reconcile.Request{}
			}

			httpRoutes = append(httpRoutes, hrList.Items...)
		}

		// Build a set of all Cilium Gateway full names.
		// This makes sure we only add a reconcile.Request once for each Gateway.
		allCiliumGatewaysSet, err := r.getAllCiliumGatewaysSet(ctx)
		if err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		// iterate through the HTTPRoutes, update reconcileRequests for each Gateway that is relevant.
		for _, hr := range httpRoutes {
			updateReconcileRequestsForParentRefs(hr.Spec.ParentRefs, hr.Namespace, allCiliumGatewaysSet, reconcileRequests)
		}

		recs := slices.Collect(maps.Keys(reconcileRequests))
		if len(recs) > 0 {
			scopedLog.Debug("BackendTLSPolicy relevant to Gateways",
				logfields.Resource, client.ObjectKeyFromObject(o).String(),
				logfields.Gateway, recs)
		}
		return slices.Collect(maps.Keys(reconcileRequests))
	})
}

func (r *gatewayReconciler) enqueueRequestForBackendTLSPolicyConfigMap() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.logger.With(logfields.LogSubsys, "queue-gw-from-backendtlspolicy-configmap")

		cfgMap, ok := o.(*corev1.ConfigMap)
		if !ok {
			return []reconcile.Request{}
		}

		cfgMapName := types.NamespacedName{
			Name:      cfgMap.GetName(),
			Namespace: cfgMap.GetNamespace(),
		}

		// Fetch all BackendTLSPolicies that reference this ConfigMap
		btlspList := &gatewayv1.BackendTLSPolicyList{}

		if err := r.Client.List(ctx, btlspList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(backendTLSPolicyConfigMapIndex, cfgMapName.String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related BackendTLSPolicies for ConfigMap", logfields.Error, err)
			return []reconcile.Request{}
		}
		// If there are no relevant BackendTLSPolicies, then we can skip this ConfigMap.
		if len(btlspList.Items) == 0 {
			return []reconcile.Request{}
		}

		// Build a set of all Cilium Gateway full names.
		// This makes sure we only add a reconcile.Request once for each Gateway.
		allCiliumGatewaysSet, err := r.getAllCiliumGatewaysSet(ctx)
		if err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		reconcileRequests := make(map[reconcile.Request]struct{})

		for _, btlsp := range btlspList.Items {

			serviceRefs := []string{}
			// First, we collect Service references from the TargetRefs
			for _, target := range btlsp.Spec.TargetRefs {
				if helpers.IsServiceTargetRef(target) {
					serviceRefs = append(serviceRefs, cfgMap.GetNamespace()+"/"+string(target.Name))
				}
			}
			httpRoutes := []gatewayv1.HTTPRoute{}

			for _, svcName := range serviceRefs {
				// Then, fetch all HTTPRoutes that reference this service, using the backendServiceIndex
				hrList := &gatewayv1.HTTPRouteList{}

				if err := r.Client.List(ctx, hrList, &client.ListOptions{
					FieldSelector: fields.OneTermEqualSelector(backendServiceHTTPRouteIndex, svcName),
				}); err != nil {
					scopedLog.ErrorContext(ctx, "Failed to get related HTTPRoutes", logfields.Error, err)
					return []reconcile.Request{}
				}

				httpRoutes = append(httpRoutes, hrList.Items...)
			}
			for _, hr := range httpRoutes {
				updateReconcileRequestsForParentRefs(hr.Spec.ParentRefs, hr.Namespace, allCiliumGatewaysSet, reconcileRequests)
			}

		}
		recs := slices.Collect(maps.Keys(reconcileRequests))
		if len(recs) > 0 {
			scopedLog.Debug("ConfigMap in BackendTLSPolicy relevant to Gateways",
				logfields.Resource, client.ObjectKeyFromObject(o).String(),
				logfields.Gateway, recs)
		}
		return recs
	})
}

func (r *gatewayReconciler) getAllCiliumGatewaysSet(ctx context.Context) (map[string]struct{}, error) {
	// Fetch all the Cilium-relevant Gateways using the implementationGatewayIndex.
	gwList := &gatewayv1.GatewayList{}
	if err := r.Client.List(ctx, gwList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(implementationGatewayIndex, "cilium"),
	}); err != nil {
		return nil, err
	}
	// Build a set of all Cilium Gateway full names.
	// This makes sure we only add a reconcile.Request once for each Gateway.
	allCiliumGatewaysSet := make(map[string]struct{})

	for _, gw := range gwList.Items {
		gwFullName := types.NamespacedName{
			Name:      gw.GetName(),
			Namespace: gw.GetNamespace(),
		}
		allCiliumGatewaysSet[gwFullName.String()] = struct{}{}
	}

	return allCiliumGatewaysSet, nil
}

// updateReconcileRequestsForParentRefs mutates the passed reconcile.Request set to add all
func updateReconcileRequestsForParentRefs(parentRefs []gatewayv1.ParentReference, ns string, allGatewaysSet map[string]struct{}, rrSet map[reconcile.Request]struct{}) {
	for _, parent := range parentRefs {
		if !helpers.IsGateway(parent) {
			continue
		}
		parentFullName := types.NamespacedName{
			Name:      string(parent.Name),
			Namespace: helpers.NamespaceDerefOr(parent.Namespace, ns),
		}
		if _, found := allGatewaysSet[parentFullName.String()]; found {
			rrSet[reconcile.Request{NamespacedName: parentFullName}] = struct{}{}
		}
	}
}

// enqueueRequestForBackendServiceImport makes sure that Gateways are reconciled
// if a relevant HTTPRoute backend Service Imports are updated.
func (r *gatewayReconciler) enqueueRequestForBackendServiceImport() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		_, ok := o.(*mcsapiv1alpha1.ServiceImport)
		if !ok {
			return nil
		}

		scopedLog := r.logger.With(logfields.LogSubsys, "queue-gw-from-backend-svc-import")

		// make a set to hold all reconcile requests
		reconcileRequests := make(map[reconcile.Request]struct{})

		// Then, fetch all HTTPRoutes that reference this service, using the backendServiceIndex
		hrList := &gatewayv1.HTTPRouteList{}

		if err := r.Client.List(ctx, hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(backendServiceImportHTTPRouteIndex, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related HTTPRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		// Fetch all the Cilium-relevant Gateways using the implementationGatewayIndex.
		gwList := &gatewayv1.GatewayList{}
		if err := r.Client.List(ctx, gwList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(implementationGatewayIndex, "cilium"),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		// Build a set of all Cilium Gateway full names.
		// This makes sure we only add a reconcile.Request once for each Gateway.
		allCiliumGatewaysSet := make(map[string]struct{})
		for _, gw := range gwList.Items {
			gwFullName := types.NamespacedName{
				Name:      gw.GetName(),
				Namespace: gw.GetNamespace(),
			}
			allCiliumGatewaysSet[gwFullName.String()] = struct{}{}
		}

		// iterate through the HTTPRoutes, return a reconcile.Request for each Gateways that is relevant.
		for _, hr := range hrList.Items {
			for _, parent := range hr.Spec.ParentRefs {
				if !helpers.IsGateway(parent) {
					continue
				}
				parentFullName := types.NamespacedName{
					Name:      string(parent.Name),
					Namespace: helpers.NamespaceDerefOr(parent.Namespace, hr.Namespace),
				}
				if _, found := allCiliumGatewaysSet[parentFullName.String()]; found {
					reconcileRequests[reconcile.Request{NamespacedName: parentFullName}] = struct{}{}
				}
			}
		}

		// return the keys of the set.
		return slices.Collect(maps.Keys(reconcileRequests))
	})
}

func getGatewayReconcileRequestsForRoute(ctx context.Context, c client.Client, object metav1.Object, route gatewayv1.CommonRouteSpec, logger *slog.Logger) []reconcile.Request {
	var reqs []reconcile.Request

	scopedLog := logger.With(
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
				scopedLog.ErrorContext(ctx, "Failed to get Gateway", logfields.Error, err)
			}
			continue
		}

		if !hasMatchingController(ctx, c, controllerName, logger)(gw) {
			scopedLog.DebugContext(ctx, "Gateway does not have matching controller, skipping")
			continue
		}

		scopedLog.InfoContext(ctx,
			"Enqueued gateway for Route",
			logfields.K8sNamespace, ns,
			logfields.ParentResource, parent.Name,
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

// enqueueRequestForTLSSecret returns an event handler for any changes with TLS secrets
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
		scopedLog := r.logger.With(
			logfields.Resource, client.ObjectKeyFromObject(o),
		)
		list := &gatewayv1.GatewayList{}

		if err := r.Client.List(ctx, list, &client.ListOptions{}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to list Gateway", logfields.Error, err)
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
			scopedLog.InfoContext(ctx, "Enqueued Gateway for resource", gateway, gw)
		}
		return requests
	}
}
