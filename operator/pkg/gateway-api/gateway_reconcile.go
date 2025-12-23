// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/policychecks"
	"github.com/cilium/cilium/operator/pkg/gateway-api/routechecks"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	"github.com/cilium/cilium/pkg/annotation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/shortener"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *gatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Resource, req.NamespacedName,
	)
	scopedLog.InfoContext(ctx, "Reconciling Gateway")

	// Step 1: Retrieve the Gateway
	original := &gatewayv1.Gateway{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		scopedLog.ErrorContext(ctx, "Unable to get Gateway", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Ignore deleting Gateway, this can happen when foregroundDeletion is enabled
	// The reconciliation loop will automatically kick off for related Gateway resources.
	if original.GetDeletionTimestamp() != nil {
		scopedLog.InfoContext(ctx, "Gateway is being deleted, doing nothing")
		return controllerruntime.Success()
	}

	gw := original.DeepCopy()

	// Step 2: Gather all required information for the ingestion model
	gwc := &gatewayv1.GatewayClass{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gwc); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to get GatewayClass",
			gatewayClass, gw.Spec.GatewayClassName,
			logfields.Error, err)
		// Doing nothing till the GatewayClass is available and matching controller name
		return controllerruntime.Success()
	}

	if string(gwc.Spec.ControllerName) != controllerName {
		scopedLog.DebugContext(ctx, "GatewayClass does not have matching controller name, doing nothing")
		return controllerruntime.Success()
	}

	httpRouteList := &gatewayv1.HTTPRouteList{}
	if err := r.Client.List(ctx, httpRouteList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.GatewayHTTPRouteIndex, client.ObjectKeyFromObject(original).String()),
	}); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list HTTPRoutes", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	grpcRouteList := &gatewayv1.GRPCRouteList{}
	if err := r.Client.List(ctx, grpcRouteList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.GatewayGRPCRouteIndex, client.ObjectKeyFromObject(original).String()),
	}); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list GRPCRoutes", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	tlsRouteList := &gatewayv1alpha2.TLSRouteList{}
	if helpers.HasTLSRouteSupport(r.Client.Scheme()) {
		if err := r.Client.List(ctx, tlsRouteList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.GatewayTLSRouteIndex, client.ObjectKeyFromObject(original).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list TLSRoutes", logfields.Error, err)
			return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
		}
	}

	btlspList := &gatewayv1.BackendTLSPolicyList{}
	if err := r.Client.List(ctx, btlspList); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list BackendTLSPolicies", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	btlspMap := helpers.BuildBackendTLSPolicyLookup(btlspList)

	// TODO(tam): Only list the services / ServiceImports used by accepted Routes
	servicesList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, servicesList); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list Services", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	serviceImportsList := &mcsapiv1alpha1.ServiceImportList{}
	if helpers.HasServiceImportSupport(r.Client.Scheme()) {
		if err := r.Client.List(ctx, serviceImportsList); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to list ServiceImports", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
	}

	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to list ReferenceGrants", logfields.Error, err)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	if gw.Spec.Infrastructure != nil && gw.Spec.Infrastructure.Annotations[annotation.LBIPAMIPKeyAlias] != "" {
		scopedLog.WarnContext(ctx, fmt.Sprintf("DEPRECATED: The Gateway <%s/%s> is setting an IP address using the infrastructure annotations <%s>."+
			" These should be set using the spec.addresses field in Gateway objects instead."+
			" At a future date this annotation will be removed if no spec.addresses are set.", gw.GetNamespace(), gw.GetName(), annotation.LBIPAMIPKeyAlias))
	}

	// Run the HTTPRoute route checks here and update the status accordingly.
	if err := r.setHTTPRouteStatuses(scopedLog, ctx, httpRouteList, grants); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update HTTPRoute Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Run the TLSRoute route checks here and update the status accordingly.
	if helpers.HasTLSRouteSupport(r.Client.Scheme()) {
		if err := r.setTLSRouteStatuses(scopedLog, ctx, tlsRouteList, grants); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to update HTTPRoute Status", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
	}

	// Run the GRPCRoute route checks here and update the status accordingly.
	if err := r.setGRPCRouteStatuses(scopedLog, ctx, grpcRouteList, grants); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update GRPCRoute Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	httpRoutes := r.filterHTTPRoutesByGateway(ctx, gw, httpRouteList.Items)
	tlsRoutes := r.filterTLSRoutesByGateway(ctx, gw, tlsRouteList.Items)
	grpcRoutes := r.filterGRPCRoutesByGateway(ctx, gw, grpcRouteList.Items)

	if err := r.setBackendTLSPolicyStatuses(scopedLog, ctx, httpRoutes, btlspMap, req.NamespacedName); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update BackendTLSPolicy Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	httpListeners, tlsPassthroughListeners := ingestion.GatewayAPI(ingestion.Input{
		GatewayClass:        *gwc,
		GatewayClassConfig:  r.getGatewayClassConfig(ctx, gwc),
		Gateway:             *gw,
		HTTPRoutes:          httpRoutes,
		TLSRoutes:           tlsRoutes,
		GRPCRoutes:          grpcRoutes,
		Services:            servicesList.Items,
		ServiceImports:      serviceImportsList.Items,
		ReferenceGrants:     grants.Items,
		BackendTLSPolicyMap: btlspMap,
	})

	validListener, err := r.setListenerStatus(ctx, gw, httpRouteList, tlsRouteList, grpcRouteList)
	if err != nil {
		scopedLog.ErrorContext(ctx, "Unable to set listener status", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to set listener status", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to set listener status", gatewayv1.GatewayReasonListenersNotValid)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	if !validListener {
		err := fmt.Errorf("No Accepted Listeners for Gateway")
		scopedLog.ErrorContext(ctx, "No Accepted Listeners for Gateway", logfields.Error, err)
		setGatewayAccepted(gw, false, "No Accepted Listeners", gatewayv1.GatewayReasonListenersNotValid)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "No Accepted Listeners", gatewayv1.GatewayReasonListenersNotValid)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	setGatewayAccepted(gw, true, "Gateway successfully scheduled", gatewayv1.GatewayReasonAccepted)

	// Step 3: Translate the listeners into Cilium model
	cec, svc, ep, err := r.translator.Translate(&model.Model{HTTP: httpListeners, TLSPassthrough: tlsPassthroughListeners})
	if err != nil {
		scopedLog.ErrorContext(ctx, "Unable to translate resources", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to translate resources", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to translate resources", gatewayv1.GatewayReasonListenersNotValid)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	if err = r.verifyGatewayStaticAddresses(gw); err != nil {
		scopedLog.ErrorContext(ctx, "Unsupported Gateway address", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unsupported Gateway address, "+err.Error(), gatewayv1.GatewayReasonUnsupportedAddress)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Address is not ready", gatewayv1.GatewayReasonListenersNotReady)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}
	if err = r.ensureService(ctx, svc); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to create Service", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to create Service resource", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to create Service resource", gatewayv1.GatewayReasonNoResources)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err = r.ensureEndpointSlice(ctx, ep); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to ensure Endpoints", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to ensure Endpoints resource", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to create Endpoints resource", gatewayv1.GatewayReasonNoResources)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err = r.ensureEnvoyConfig(ctx, cec); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to ensure CiliumEnvoyConfig", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to ensure CEC resource", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to create CEC resource", gatewayv1.GatewayReasonNoResources)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	setGatewayProgrammed(gw, metav1.ConditionFalse, "Gateway waiting for address", gatewayv1.GatewayReasonAddressNotAssigned)

	// Step 4: Update the status of the Gateway
	if err = r.setAddressStatus(ctx, gw); err != nil {
		scopedLog.ErrorContext(ctx, "Address is not ready", logfields.Error, err)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Address is not ready, "+err.Error(), gatewayv1.GatewayReasonAddressNotAssigned)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err = r.setStaticAddressStatus(ctx, gw); err != nil {
		scopedLog.ErrorContext(ctx, "StaticAddress can't be used", logfields.Error, err)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "StaticAddress can't be used", gatewayv1.GatewayReasonAddressNotUsable)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err := r.updateStatus(ctx, original, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update Gateway status: %w", err)
	}

	scopedLog.InfoContext(ctx, "Successfully reconciled Gateway")
	return controllerruntime.Success()
}

func (r *gatewayReconciler) ensureService(ctx context.Context, desired *corev1.Service) error {
	svc := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, svc, func() error {
		// Save and restore loadBalancerClass
		// e.g. if a mutating webhook writes this field
		lbClass := svc.Spec.LoadBalancerClass
		svc.Spec = desired.Spec
		svc.OwnerReferences = desired.OwnerReferences
		setMergedLabelsAndAnnotations(svc, desired)

		// Ignore the loadBalancerClass if it was set by a mutating webhook
		svc.Spec.LoadBalancerClass = lbClass
		return nil
	})
	return err
}

func (r *gatewayReconciler) ensureEndpointSlice(ctx context.Context, desired *discoveryv1.EndpointSlice) error {
	eps := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, eps, func() error {
		eps.Endpoints = desired.Endpoints
		eps.Ports = desired.Ports
		eps.OwnerReferences = desired.OwnerReferences
		setMergedLabelsAndAnnotations(eps, desired)
		return nil
	})
	return err
}

func (r *gatewayReconciler) ensureEnvoyConfig(ctx context.Context, desired *ciliumv2.CiliumEnvoyConfig) error {
	cec := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, cec, func() error {
		cec.Spec = desired.Spec
		setMergedLabelsAndAnnotations(cec, desired)
		return nil
	})
	return err
}

func (r *gatewayReconciler) updateStatus(ctx context.Context, original *gatewayv1.Gateway, new *gatewayv1.Gateway) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) filterHTTPRoutesByGateway(ctx context.Context, gw *gatewayv1.Gateway, routes []gatewayv1.HTTPRoute) []gatewayv1.HTTPRoute {
	var filtered []gatewayv1.HTTPRoute
	allListenerHostNames := routechecks.GetAllListenerHostNames(gw.Spec.Listeners)
	for _, route := range routes {
		if isAttachable(ctx, gw, &route, route.Status.Parents) && isAllowed(ctx, r.Client, gw, &route, r.logger) && len(computeHosts(gw, route.Spec.Hostnames, allListenerHostNames)) > 0 {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (r *gatewayReconciler) filterGRPCRoutesByGateway(ctx context.Context, gw *gatewayv1.Gateway, routes []gatewayv1.GRPCRoute) []gatewayv1.GRPCRoute {
	var filtered []gatewayv1.GRPCRoute
	allListenerHostNames := routechecks.GetAllListenerHostNames(gw.Spec.Listeners)

	for _, route := range routes {
		if isAttachable(ctx, gw, &route, route.Status.Parents) && isAllowed(ctx, r.Client, gw, &route, r.logger) && len(computeHosts(gw, route.Spec.Hostnames, allListenerHostNames)) > 0 {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (r *gatewayReconciler) filterHTTPRoutesByListener(ctx context.Context, gw *gatewayv1.Gateway, listener *gatewayv1.Listener, routes []gatewayv1.HTTPRoute) []gatewayv1.HTTPRoute {
	var filtered []gatewayv1.HTTPRoute
	for _, route := range routes {
		if isAttachable(ctx, gw, &route, route.Status.Parents) &&
			isAllowed(ctx, r.Client, gw, &route, r.logger) &&
			len(computeHostsForListener(listener, route.Spec.Hostnames, nil)) > 0 &&
			parentRefMatched(gw, listener, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (r *gatewayReconciler) filterGRPCRoutesByListener(ctx context.Context, gw *gatewayv1.Gateway, listener *gatewayv1.Listener, routes []gatewayv1.GRPCRoute) []gatewayv1.GRPCRoute {
	var filtered []gatewayv1.GRPCRoute
	for _, route := range routes {
		if isAttachable(ctx, gw, &route, route.Status.Parents) &&
			isAllowed(ctx, r.Client, gw, &route, r.logger) &&
			len(computeHostsForListener(listener, route.Spec.Hostnames, nil)) > 0 &&
			parentRefMatched(gw, listener, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

// getGatewayClassConfig returns the CiliumGatewayClassConfig referenced by the GatewayClass.
// If the GatewayClass does not reference a CiliumGatewayClassConfig, it returns nil.
func (r *gatewayReconciler) getGatewayClassConfig(ctx context.Context, gwc *gatewayv1.GatewayClass) *v2alpha1.CiliumGatewayClassConfig {
	if gwc.Spec.ParametersRef == nil ||
		gwc.Spec.ParametersRef.Group != v2alpha1.CustomResourceDefinitionGroup ||
		gwc.Spec.ParametersRef.Kind != v2alpha1.CGCCKindDefinition {
		return nil
	}

	res := &v2alpha1.CiliumGatewayClassConfig{}
	if err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: string(*gwc.Spec.ParametersRef.Namespace),
		Name:      gwc.Spec.ParametersRef.Name,
	}, res); err != nil {
		return nil
	}
	return res
}

func parentRefMatched(gw *gatewayv1.Gateway, listener *gatewayv1.Listener, routeNamespace string, refs []gatewayv1.ParentReference) bool {
	for _, ref := range refs {
		// Check if the parentRef is a Gateway before checking name and namespace
		if !helpers.IsGateway(ref) {
			continue
		}

		if string(ref.Name) == gw.GetName() && gw.GetNamespace() == helpers.NamespaceDerefOr(ref.Namespace, routeNamespace) {
			if ref.SectionName == nil && ref.Port == nil {
				return true
			}
			sectionNameCheck := ref.SectionName == nil || *ref.SectionName == listener.Name
			portCheck := ref.Port == nil || *ref.Port == listener.Port
			if sectionNameCheck && portCheck {
				return true
			}
		}
	}
	return false
}

func (r *gatewayReconciler) filterTLSRoutesByGateway(ctx context.Context, gw *gatewayv1.Gateway, routes []gatewayv1alpha2.TLSRoute) []gatewayv1alpha2.TLSRoute {
	var filtered []gatewayv1alpha2.TLSRoute
	for _, route := range routes {
		if isAttachable(ctx, gw, &route, route.Status.Parents) && isAllowed(ctx, r.Client, gw, &route, r.logger) &&
			len(computeHosts(gw, route.Spec.Hostnames, nil)) > 0 {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (r *gatewayReconciler) filterTLSRoutesByListener(ctx context.Context, gw *gatewayv1.Gateway, listener *gatewayv1.Listener, routes []gatewayv1alpha2.TLSRoute) []gatewayv1alpha2.TLSRoute {
	var filtered []gatewayv1alpha2.TLSRoute
	for _, route := range routes {
		if isAttachable(ctx, gw, &route, route.Status.Parents) &&
			isAllowed(ctx, r.Client, gw, &route, r.logger) &&
			len(computeHostsForListener(listener, route.Spec.Hostnames, nil)) > 0 &&
			parentRefMatched(gw, listener, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func isAttachable(_ context.Context, gw *gatewayv1.Gateway, route metav1.Object, parents []gatewayv1.RouteParentStatus) bool {
	for _, rps := range parents {
		if helpers.NamespaceDerefOr(rps.ParentRef.Namespace, route.GetNamespace()) != gw.GetNamespace() ||
			string(rps.ParentRef.Name) != gw.GetName() {
			continue
		}

		for _, cond := range rps.Conditions {
			if cond.Type == string(gatewayv1.RouteConditionAccepted) && cond.Status == metav1.ConditionTrue {
				return true
			}

			if cond.Type == string(gatewayv1.RouteConditionResolvedRefs) && cond.Status == metav1.ConditionFalse {
				return true
			}
		}
	}
	return false
}

func (r *gatewayReconciler) setAddressStatus(ctx context.Context, gw *gatewayv1.Gateway) error {
	r.logger.InfoContext(ctx, "Checking address status for Gateway", logfields.Resource, client.ObjectKeyFromObject(gw).String())
	svcList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, svcList, client.MatchingLabels{
		owningGatewayLabel: shortener.ShortenK8sResourceName(gw.GetName()),
	}, client.InNamespace(gw.GetNamespace())); err != nil {
		return err
	}

	if len(svcList.Items) == 0 {
		return fmt.Errorf("no service found")
	}

	svc := svcList.Items[0]
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		// Potential loadbalancer service isn't ready yet. No need to report as an error, because
		// reconciliation should be triggered when the loadbalancer services gets updated.
		return nil
	}

	var addresses []gatewayv1.GatewayStatusAddress
	for _, s := range svc.Status.LoadBalancer.Ingress {
		if len(s.IP) != 0 {
			addresses = append(addresses, gatewayv1.GatewayStatusAddress{
				Type:  GatewayAddressTypePtr(gatewayv1.IPAddressType),
				Value: s.IP,
			})
		}
		if len(s.Hostname) != 0 {
			addresses = append(addresses, gatewayv1.GatewayStatusAddress{
				Type:  GatewayAddressTypePtr(gatewayv1.HostnameAddressType),
				Value: s.Hostname,
			})
		}
	}

	if len(addresses) > 0 {
		r.logger.InfoContext(ctx, "At least one valid address, marking gateway programmed", logfields.Resource, client.ObjectKeyFromObject(gw).String())
		setGatewayProgrammed(gw, metav1.ConditionTrue, "Gateway Programmed", gatewayv1.GatewayReasonProgrammed)
		for _, l := range gw.Status.Listeners {
			// Is Listener Accepted?
			accepted := false

			for _, cond := range l.Conditions {
				if cond.Type == string(gatewayv1.GatewayConditionAccepted) &&
					cond.Status == metav1.ConditionTrue {
					accepted = true
					break
				}
			}
			if accepted {
				l.Conditions = merge(l.Conditions, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionProgrammed),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonProgrammed),
					Message:            "Listener Programmed",
					ObservedGeneration: gw.Generation,
					LastTransitionTime: metav1.Now(),
				})
			}
		}
	}
	gw.Status.Addresses = addresses
	return nil
}

func (r *gatewayReconciler) setStaticAddressStatus(ctx context.Context, gw *gatewayv1.Gateway) error {
	if len(gw.Spec.Addresses) == 0 {
		return nil
	}
	svcList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, svcList, client.MatchingLabels{
		owningGatewayLabel: shortener.ShortenK8sResourceName(gw.GetName()),
	}, client.InNamespace(gw.GetNamespace())); err != nil {
		return err
	}

	if len(svcList.Items) == 0 {
		return fmt.Errorf("no service found")
	}

	svc := svcList.Items[0]
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		// Potential loadbalancer service isn't ready yet. No need to report as an error, because
		// reconciliation should be triggered when the loadbalancer services gets updated.
		return nil
	}
	addresses := make(map[string]struct{})
	for _, addr := range svc.Status.LoadBalancer.Ingress {
		addresses[addr.IP] = struct{}{}
	}

	for _, addr := range gw.Spec.Addresses {
		if _, ok := addresses[addr.Value]; !ok {
			return fmt.Errorf("static address %q can't be used", addr.Value)
		}
	}

	return nil
}

func (r *gatewayReconciler) setListenerStatus(ctx context.Context, gw *gatewayv1.Gateway, httpRoutes *gatewayv1.HTTPRouteList, tlsRoutes *gatewayv1alpha2.TLSRouteList, grpcRoutes *gatewayv1.GRPCRouteList) (bool, error) {
	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return false, fmt.Errorf("failed to retrieve reference grants: %w", err)
	}

	// Keep track of if there is at least one Valid Listener; if not, the Gateway cannot be Accepted.
	oneValidListener := false
	for _, l := range gw.Spec.Listeners {
		isValid := true
		var invalidMessages []string

		var conds []metav1.Condition

		allSupported := getSupportedRouteKinds(l.Protocol)
		if allSupported == nil {
			invalidMessages = append(invalidMessages, "Unsupported Listener Protocol.")
			isValid = false
		}
		supportedKinds := []gatewayv1.RouteGroupKind{}

		if l.AllowedRoutes != nil && len(l.AllowedRoutes.Kinds) > 0 {
			for _, supported := range allSupported {
				for _, allowed := range l.AllowedRoutes.Kinds {
					if supported.Kind == allowed.Kind &&
						groupDerefOr(allowed.Group, gatewayv1.GroupName) == string(*supported.Group) {
						supportedKinds = append(supportedKinds, supported)
						break
					}
				}
			}

			// Add ResolvedRefs if not all explicitly allowed kinds are actually supported
			if len(supportedKinds) != len(l.AllowedRoutes.Kinds) {
				conds = merge(conds, gatewayListenerInvalidRouteKinds(gw, "Unsupported Route Kinds in allowedRoutes.kinds"))
			}

			if len(supportedKinds) == 0 {
				invalidMessages = append(invalidMessages, "None of the Allowed Route Kinds are supported.")
				isValid = false
			}
		} else {
			// If there are no Kinds specified in AllowedRoutes, then supportedKinds should contain
			// all the supported Kinds for that Protocol.
			supportedKinds = allSupported
		}

		if l.TLS != nil {
			for _, cert := range l.TLS.CertificateRefs {
				if !helpers.IsSecret(cert) {
					conds = merge(conds, metav1.Condition{
						Type:               string(gatewayv1.ListenerConditionResolvedRefs),
						Status:             metav1.ConditionFalse,
						Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
						Message:            "Invalid CertificateRef",
						LastTransitionTime: metav1.Now(),
					})
					invalidMessages = append(invalidMessages, "Invalid CertificateRef, must be a Secret.")
					isValid = false
					break
				}

				if !helpers.IsSecretReferenceAllowed(gw.Namespace, cert, gatewayv1.SchemeGroupVersion.WithKind("Gateway"), grants.Items) {
					conds = merge(conds, metav1.Condition{
						Type:               string(gatewayv1.ListenerConditionResolvedRefs),
						Status:             metav1.ConditionFalse,
						Reason:             string(gatewayv1.ListenerReasonRefNotPermitted),
						Message:            "CertificateRef is not permitted",
						LastTransitionTime: metav1.Now(),
					})
					invalidMessages = append(invalidMessages, "Invalid CertificateRef, not permitted.")
					isValid = false
					break
				}

				if err := validateTLSSecret(ctx, r.Client, helpers.NamespaceDerefOr(cert.Namespace, gw.GetNamespace()), string(cert.Name)); err != nil {
					r.logger.InfoContext(ctx, "Found an invalid TLS Secret",
						logfields.Error, err.Error(),
						logfields.Resource, client.ObjectKeyFromObject(gw).String())
					conds = merge(conds, metav1.Condition{
						Type:               string(gatewayv1.ListenerConditionResolvedRefs),
						Status:             metav1.ConditionFalse,
						Reason:             string(gatewayv1.ListenerReasonInvalidCertificateRef),
						Message:            "Invalid CertificateRef",
						LastTransitionTime: metav1.Now(),
					})
					invalidMessages = append(invalidMessages, "Invalid CertificateRef, "+err.Error())
					isValid = false
					break
				}
			}
		}

		if !isValid {
			conds = merge(conds,
				gatewayListenerAcceptedCondition(gw, false, "Listener not valid. "+strings.Join(invalidMessages, " ")),
				gatewayListenerProgrammedCondition(gw, false, "Address not ready yet"))
		} else {
			// There's at least one Accepted listener, so the Gateway can also be Accepted.
			oneValidListener = true
			// If ResolvedRefs is not already present, add a successful one.
			if !helpers.IsConditionPresent(conds, string(gatewayv1.ListenerConditionResolvedRefs)) {
				conds = merge(conds, metav1.Condition{
					Type:               string(gatewayv1.ListenerConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerReasonResolvedRefs),
					Message:            "Resolved Refs",
					ObservedGeneration: gw.GetGeneration(),
					LastTransitionTime: metav1.Now(),
				})
			}
			conds = merge(conds,
				gatewayListenerAcceptedCondition(gw, true, "Listener Accepted"),
				gatewayListenerProgrammedCondition(gw, false, "Address not ready yet"))
		}
		var attachedRoutes int32
		attachedRoutes += int32(len(r.filterHTTPRoutesByListener(ctx, gw, &l, httpRoutes.Items)))
		attachedRoutes += int32(len(r.filterGRPCRoutesByListener(ctx, gw, &l, grpcRoutes.Items)))
		attachedRoutes += int32(len(r.filterTLSRoutesByListener(ctx, gw, &l, tlsRoutes.Items)))

		found := false
		for i := range gw.Status.Listeners {
			if l.Name == gw.Status.Listeners[i].Name {
				found = true
				gw.Status.Listeners[i].SupportedKinds = supportedKinds
				gw.Status.Listeners[i].Conditions = conds
				gw.Status.Listeners[i].AttachedRoutes = attachedRoutes
				break
			}
		}
		if !found {
			gw.Status.Listeners = append(gw.Status.Listeners, gatewayv1.ListenerStatus{
				Name:           l.Name,
				SupportedKinds: supportedKinds,
				Conditions:     conds,
				AttachedRoutes: attachedRoutes,
			})
		}
	}

	// filter listener status to only have active listeners
	var newListenersStatus []gatewayv1.ListenerStatus
	for _, ls := range gw.Status.Listeners {
		for _, l := range gw.Spec.Listeners {
			if ls.Name == l.Name {
				newListenersStatus = append(newListenersStatus, ls)
				break
			}
		}
	}
	gw.Status.Listeners = newListenersStatus
	return oneValidListener, nil
}

func validateTLSSecret(ctx context.Context, c client.Client, namespace, name string) error {
	secret := &corev1.Secret{}
	if err := c.Get(ctx, client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}, secret); err != nil {
		return err
	}

	if !isValidPemFormat(secret.Data[corev1.TLSCertKey]) {
		return fmt.Errorf("PEM format error in TLS Certificate")
	}

	if !isValidPemFormat(secret.Data[corev1.TLSPrivateKeyKey]) {
		return fmt.Errorf("PEM format error in TLS Key")
	}
	return nil
}

// isValidPemFormat checks if the given byte array contains at least one valid PEM
// formatted object, either certificate or key.
// This function is not intended to be used for validating the actual
// content of the PEM block.
func isValidPemFormat(b []byte) bool {
	if len(b) == 0 {
		return false
	}

	p, rest := pem.Decode(b)
	if p == nil {
		return false
	}
	if len(rest) == 0 {
		return true
	}

	// We don't check the value of `rest` because
	// Envoy will be able to parse the file as long as there
	// is at least one valid certificate.
	return true
}

func (r *gatewayReconciler) handleReconcileErrorWithStatus(ctx context.Context, reconcileErr error, original *gatewayv1.Gateway, modified *gatewayv1.Gateway) (ctrl.Result, error) {
	if err := r.updateStatus(ctx, original, modified); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err))
	}

	return controllerruntime.Fail(reconcileErr)
}

func (r *gatewayReconciler) verifyGatewayStaticAddresses(gw *gatewayv1.Gateway) error {
	if len(gw.Spec.Addresses) == 0 {
		return nil
	}
	for _, address := range gw.Spec.Addresses {
		if address.Type != nil && *address.Type != gatewayv1.IPAddressType {
			return fmt.Errorf("address type is not supported")
		}
		if address.Value == "" {
			return fmt.Errorf("address value is not set")
		}
		ip := net.ParseIP(address.Value)
		if ip == nil {
			return fmt.Errorf("invalid ip address")
		}
	}
	return nil
}

// runCommonRouteChecks runs all the checks that are common across all supported Route types.
//
// Uses the helpers.Input interface to ensure that this still applies as new types are added.
func (r *gatewayReconciler) runCommonRouteChecks(input routechecks.Input, parentRefs []gatewayv1.ParentReference, objNamespace string) error {
	for _, parent := range parentRefs {
		// If this parentRef is not a Gateway parentRef, skip it.
		if !helpers.IsGateway(parent) {
			continue
		}

		// Similarly, if this Gateway is not a matching one, skip it.
		if !r.parentIsMatchingGateway(parent, objNamespace) {
			continue
		}

		// set Accepted to okay, this wil be overwritten in checks if needed
		input.SetParentCondition(parent, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonAccepted),
			Message: "Accepted HTTPRoute",
		})

		// set ResolvedRefs to okay, this wil be overwritten in checks if needed
		input.SetParentCondition(parent, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionTrue,
			Reason:  string(gatewayv1.RouteReasonResolvedRefs),
			Message: "Service reference is valid",
		})

		// run the Gateway validators
		for _, fn := range []routechecks.CheckWithParentFunc{
			routechecks.CheckGatewayRouteKindAllowed,
			routechecks.CheckGatewayMatchingPorts,
			routechecks.CheckGatewayMatchingHostnames,
			routechecks.CheckGatewayMatchingSection,
			routechecks.CheckGatewayAllowedForNamespace,
		} {
			continueCheck, err := fn(input, parent)
			if err != nil {
				return fmt.Errorf("failed to apply Gateway check: %w", err)
			}

			if !continueCheck {
				break
			}
		}

		// Run the Rule validators, these need to be run per-parent so that we
		// don't update status for parents we don't own.
		for _, fn := range []routechecks.CheckWithParentFunc{
			routechecks.CheckAgainstCrossNamespaceBackendReferences,
			routechecks.CheckBackend,
			routechecks.CheckHasServiceImportSupport,
			routechecks.CheckBackendIsExistingService,
		} {
			continueCheck, err := fn(input, parent)
			if err != nil {
				return fmt.Errorf("failed to apply Backend check: %w", err)
			}

			if !continueCheck {
				break
			}
		}

	}

	return nil
}

func (r *gatewayReconciler) parentIsMatchingGateway(parent gatewayv1.ParentReference, namespace string) bool {
	hasMatchingControllerFn := hasMatchingController(context.Background(), r.Client, controllerName, r.logger)
	if !helpers.IsGateway(parent) {
		return false
	}
	gw := &gatewayv1.Gateway{}
	if err := r.Client.Get(context.Background(), types.NamespacedName{
		Namespace: helpers.NamespaceDerefOr(parent.Namespace, namespace),
		Name:      string(parent.Name),
	}, gw); err != nil {
		return false
	}
	return hasMatchingControllerFn(gw)
}

func (r *gatewayReconciler) setHTTPRouteStatuses(scopedLog *slog.Logger, ctx context.Context, httpRoutes *gatewayv1.HTTPRouteList, grants *gatewayv1beta1.ReferenceGrantList) error {
	scopedLog.DebugContext(ctx, "Updating HTTPRoute statuses for Gateway", numRoutes, len(httpRoutes.Items))
	for httpRouteIndex, original := range httpRoutes.Items {

		hr := original.DeepCopy()

		// input for the validators
		// The validators will mutate the HTTPRoute as required, setting its status correctly.
		i := &routechecks.HTTPRouteInput{
			Ctx:       ctx,
			Logger:    scopedLog.With(logfields.HTTPRoute, hr),
			Client:    r.Client,
			Grants:    grants,
			HTTPRoute: hr,
		}

		if err := r.runCommonRouteChecks(i, hr.Spec.ParentRefs, hr.Namespace); err != nil {
			return r.handleHTTPRouteReconcileErrorWithStatus(ctx, scopedLog, err, &original, hr)
		}

		// Route-specific checks will go in here separately if required.

		// Validate the HTTPRoute header name
		if err := i.ValidateHeaderModifier(); err != nil {
			return r.handleHTTPRouteReconcileErrorWithStatus(ctx, scopedLog, err, &original, hr)
		}

		// Checks finished, apply the status to the actual objects.
		if err := r.updateHTTPRouteStatus(ctx, scopedLog, &original, hr); err != nil {
			return fmt.Errorf("failed to update HTTPRoute status: %w", err)
		}

		// Update the cached copy with the same status changes to prevent re-fetching from client cache.
		httpRoutes.Items[httpRouteIndex].Status = hr.Status
	}

	return nil
}

func (r *gatewayReconciler) setTLSRouteStatuses(scopedLog *slog.Logger, ctx context.Context, tlsRoutes *gatewayv1alpha2.TLSRouteList, grants *gatewayv1beta1.ReferenceGrantList) error {
	scopedLog.Debug("Updating TLSRoute statuses for Gateway", numRoutes, len(tlsRoutes.Items))
	for tlsRouteIndex, original := range tlsRoutes.Items {

		tlsr := original.DeepCopy()

		// input for the validators
		// The validators will mutate the HTTPRoute as required, setting its status correctly.
		i := &routechecks.TLSRouteInput{
			Ctx:      ctx,
			Logger:   scopedLog.With(logfields.TLSRoute, tlsr),
			Client:   r.Client,
			Grants:   grants,
			TLSRoute: tlsr,
		}

		if err := r.runCommonRouteChecks(i, tlsr.Spec.ParentRefs, tlsr.Namespace); err != nil {
			return r.handleTLSRouteReconcileErrorWithStatus(ctx, scopedLog, err, tlsr, &original)
		}

		// Route-specific checks will go in here separately if required.

		// Checks finished, apply the status to the actual objects.
		if err := r.updateTLSRouteStatus(ctx, scopedLog, &original, tlsr); err != nil {
			return fmt.Errorf("failed to update HTTPRoute status: %w", err)
		}

		// Update the cached copy with the same status changes to prevent re-fetching from client cache.
		tlsRoutes.Items[tlsRouteIndex].Status = tlsr.Status
	}

	return nil
}

func (r *gatewayReconciler) setGRPCRouteStatuses(scopedLog *slog.Logger, ctx context.Context, grpcRoutes *gatewayv1.GRPCRouteList, grants *gatewayv1beta1.ReferenceGrantList) error {
	scopedLog.Debug("Updating GRPCRoute statuses for Gateway", numRoutes, len(grpcRoutes.Items))
	for grpcRouteIndex, original := range grpcRoutes.Items {

		grpcr := original.DeepCopy()

		// input for the validators
		// The validators will mutate the HTTPRoute as required, setting its status correctly.
		i := &routechecks.GRPCRouteInput{
			Ctx:       ctx,
			Logger:    scopedLog.With(logfields.GRPCRoute, grpcr),
			Client:    r.Client,
			Grants:    grants,
			GRPCRoute: grpcr,
		}

		if err := r.runCommonRouteChecks(i, grpcr.Spec.ParentRefs, grpcr.Namespace); err != nil {
			return r.handleGRPCRouteReconcileErrorWithStatus(ctx, scopedLog, err, grpcr, &original)
		}

		// Route-specific checks will go in here separately if required.

		// Checks finished, apply the status to the actual objects.
		if err := r.updateGRPCRouteStatus(ctx, scopedLog, &original, grpcr); err != nil {
			return fmt.Errorf("failed to update HTTPRoute status: %w", err)
		}

		// Update the cached copy with the same status changes to prevent re-fetching from client cache.
		grpcRoutes.Items[grpcRouteIndex].Status = grpcr.Status
	}

	return nil
}

func (r *gatewayReconciler) setBackendTLSPolicyStatuses(scopedLog *slog.Logger,
	ctx context.Context,
	httpRoutes []gatewayv1.HTTPRoute,
	btlspMap helpers.BackendTLSPolicyServiceMap,
	gatewayName types.NamespacedName,
) error {
	scopedLog.Debug("Updating BackendTLSPolicy statuses for Gateway", policies, len(btlspMap))

	currentGatewayRef := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: (*gatewayv1.Namespace)(&gatewayName.Namespace),
		Name:      gatewayv1.ObjectName(gatewayName.Name),
	}

	// TODO(youngnick): There's currently a corner case error in the design upstream,
	// as there is no way to solve for the case that:
	// * A BackendTLSPolicy has multiple targetRefs
	// * the multiple targetRefs point to backends used in HTTPRoutes that roll up to the same
	//   Gateway
	// * Some of the targetRefs exist and some do not.
	//
	// What happens in this case is currently undefined upstream, as we only namespace the BackendTLSPolicy
	// status by Gateway.
	//
	// This code currently errs on the side of marking the BackendTLSPolicy as Accepted,
	// with ResolvedRefs: False, as long as at least one targetRef is valid, and there are
	// other targetRefs that are not valid.

	// confirmedValidBTLSPs maintains a set of all BackendTLSPolicies that
	// have at least one targetRef that is valid for the currentGatewayRef.
	//
	// This map will only be populated if at least one of the targetRefs in that
	// Policy passes all the checks and is valid.
	//
	// This is then used both as a flag to see if other targetRefs in the same
	// Policy should create status updates or not.
	confirmedValidBTLSPs := make(map[types.NamespacedName]struct{})

	// svcNames have already had the conflict-resolution rules applied to build the btlspMap.
	// So, we can rely both on them being correct, and being referenced in the BackendTLSPolicy.
	// For each svcName, check if that service rolls up to a relevant Gateway
	// and run any required Policy checks, like if the Service exists.
	for svcName, collection := range btlspMap {
		// We have to find if BackendTLSPolicy is used in the current Gateway, so we can set the
		// status.

		// First, we get all the HTTPRoutes that have the targetRef service as a backend
		hrList := &gatewayv1.HTTPRouteList{}

		if err := r.Client.List(ctx, hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.BackendServiceHTTPRouteIndex, svcName.String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related HTTPRoutes", logfields.Error, err)
			return err
		}

		found, err := ContainsCommonHTTPRoute(hrList.Items, httpRoutes)
		if err != nil {
			// There was a common HTTPRoute found, but the generation was different, error out from this.
			return err
		}
		if !found {
			// This service is not used in the current Gateway, so we can skip it.
			continue
		}

		scopedLog.Debug("collection", policies, collection)
		// next thing, see if the referenced service exists. If not, we can just reject all the
		// BackendTLSPolicies regardless of which one got accepted.
		obj := &corev1.Service{}
		err = r.Client.Get(ctx, svcName, obj)
		if err != nil {
			if !k8serrors.IsNotFound(err) {
				// if it is not just a not found error, we should return the error as something is bad
				return fmt.Errorf("error while checking Backend Service: %w", err)
			}
			// If the Service does not exist, all referenced BackendTLSPolicies must be
			// Accepted: False, with reason Conflicted.
			for _, original := range collection.Valid {
				btlspFullName := types.NamespacedName{
					Name:      original.GetName(),
					Namespace: original.GetNamespace(),
				}

				if _, ok := confirmedValidBTLSPs[btlspFullName]; ok {
					// If the BackendTLSPolicy is already listed in the btlspStatus,
					// then we've already confirmed it's valid, so we need to skip updating
					// the status with errors.
					continue
				}

				btlsp := original.DeepCopy()

				input := &policychecks.BackendTLSPolicyInput{
					Ctx:              ctx,
					Logger:           scopedLog.With(logfields.BackendTLSPolicy, client.ObjectKeyFromObject(original)),
					Client:           r.Client,
					BackendTLSPolicy: btlsp,
				}
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.PolicyConditionAccepted),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.PolicyReasonInvalid),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				// Checks finished, apply the status to the actual objects.
				if err := r.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
					return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
				}
				// Update the original with the updated status
				original.Status = btlsp.Status
			}

			// Second, for any Conflicted BackendTLSPolicies, we can set them to Conflicted and move on.
			for _, original := range collection.Conflicted {
				btlspFullName := types.NamespacedName{
					Name:      original.GetName(),
					Namespace: original.GetNamespace(),
				}

				btlsp := original.DeepCopy()

				if _, ok := confirmedValidBTLSPs[btlspFullName]; ok {
					// If the BackendTLSPolicy is already listed in the btlspStatus,
					// then we've already confirmed it's valid, so we need to skip updating
					// the status with errors.
					continue
				}
				input := &policychecks.BackendTLSPolicyInput{
					Ctx:              ctx,
					Logger:           scopedLog.With(logfields.BackendTLSPolicy, client.ObjectKeyFromObject(original)),
					Client:           r.Client,
					BackendTLSPolicy: btlsp,
				}
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.PolicyConditionAccepted),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.PolicyReasonInvalid),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				// Checks finished, apply the status to the actual objects.
				if err := r.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
					return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
				}
				// Update the original with the updated status
				original.Status = btlsp.Status
			}
			// Continue, because this Service doesn't exist
			continue
		}

		// Lastly, pull out any valid BackendTLSPolicies, then check them.
		// The SectionName logic has already deduplicated them, so we don't actually need to track
		// the sectionName here.

		validBTLSPs := collection.Valid
		for _, original := range validBTLSPs {

			btlsp := original.DeepCopy()

			// input for the validators
			// The validators will mutate the BackendTLSPolicy as required, setting its status correctly.
			input := &policychecks.BackendTLSPolicyInput{
				Ctx:              ctx,
				Logger:           scopedLog.With(logfields.BackendTLSPolicy, client.ObjectKeyFromObject(btlsp)),
				Client:           r.Client,
				BackendTLSPolicy: btlsp,
			}

			// Now, we run the Policy checks against it, which will update the status correctly.

			// So we can update the status of that BackendTLSPolicy with the name of the current Gateway.

			// set Accepted to okay, this will be overwritten in checks if needed
			input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
				Type:    string(gatewayv1.PolicyConditionAccepted),
				Status:  metav1.ConditionTrue,
				Reason:  string(gatewayv1.PolicyReasonAccepted),
				Message: "Accepted BackendTLSPolicy",
			})

			// set ResolvedRefs to okay, this wil be overwritten in checks if needed
			input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
				Type:    string(gatewayv1.RouteConditionResolvedRefs),
				Status:  metav1.ConditionTrue,
				Reason:  string(gatewayv1.RouteReasonResolvedRefs),
				Message: "All references are valid",
			})
			input.Logger.Debug("Validating BackendTLSPolicy spec")
			valid, err := input.ValidateSpec(currentGatewayRef)
			if err != nil {
				return fmt.Errorf("failed to validate BackendTLSPolicy spec: %w", err)
			}
			if valid {
				// This BackendTLSPolicy is valid, so we can add the original status to the btlspStatus
				// lookup map. It's okay to do this multiple times, since the original status will be the same.
				confirmedValidBTLSPs[types.NamespacedName{
					Name:      btlsp.GetName(),
					Namespace: btlsp.GetNamespace(),
				}] = struct{}{}
			}

			// Checks finished, apply the status to the actual objects.
			if err := r.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
				return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
			}
			// Update the original with the updated status
			original.Status = btlsp.Status
		}

		// We can set Conflicted BTLSPs conditions now.
		for _, original := range collection.Conflicted {
			btlsp := original.DeepCopy()

			// input for the validators
			// The validators will mutate the BackendTLSPolicy as required, setting its status correctly.
			input := &policychecks.BackendTLSPolicyInput{
				Ctx:              ctx,
				Logger:           scopedLog.With(logfields.BackendTLSPolicy, client.ObjectKeyFromObject(btlsp)),
				Client:           r.Client,
				BackendTLSPolicy: btlsp,
			}

			input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
				Type:    string(gatewayv1.PolicyConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.PolicyReasonConflicted),
				Message: "BackendTLSPolicy conflicts with another",
			})
			// Checks finished, apply the status to the actual objects.
			if err := r.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
				return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
			}
			// Update the original with the updated status
			original.Status = btlsp.Status

		}
	}
	return nil
}

// ContainsCommonHTTPRoute checks to see if the two slices of HTTPRoutes contain
// at least one identical HTTPRoute. If so, returns true.
//
// Returns an error if the two lists contain a HTTPRoute that is the same object
// with a different generation; this means there has been a HTTPRoute update
// between when the two lists were generated, and the whole reconciliation must be
// restarted.
func ContainsCommonHTTPRoute(a, b []gatewayv1.HTTPRoute) (bool, error) {
	for _, hrA := range a {
		for _, hrB := range b {
			same, err := helpers.ObjectsEqual(&hrA, &hrB)
			if err != nil {
				return true, err
			}
			if same {
				return true, nil
			}
		}
	}
	return false, nil
}

func (r *gatewayReconciler) handleHTTPRouteReconcileErrorWithStatus(ctx context.Context, scopedLog *slog.Logger, reconcileErr error, original *gatewayv1.HTTPRoute, modified *gatewayv1.HTTPRoute) error {
	if err := r.updateHTTPRouteStatus(ctx, scopedLog, original, modified); err != nil {
		return fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err)
	}
	return nil
}

func (r *gatewayReconciler) updateHTTPRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.HTTPRoute, new *gatewayv1.HTTPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.DebugContext(ctx, "Updating HTTPRoute status", httpRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) handleTLSRouteReconcileErrorWithStatus(ctx context.Context, scopedLog *slog.Logger, reconcileErr error, original *gatewayv1alpha2.TLSRoute, modified *gatewayv1alpha2.TLSRoute) error {
	if err := r.updateTLSRouteStatus(ctx, scopedLog, original, modified); err != nil {
		return fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err)
	}
	return nil
}

func (r *gatewayReconciler) updateTLSRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1alpha2.TLSRoute, new *gatewayv1alpha2.TLSRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("Updating TLSRoute status", tlsRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) handleGRPCRouteReconcileErrorWithStatus(ctx context.Context, scopedLog *slog.Logger, reconcileErr error, original *gatewayv1.GRPCRoute, modified *gatewayv1.GRPCRoute) error {
	if err := r.updateGRPCRouteStatus(ctx, scopedLog, original, modified); err != nil {
		return fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err)
	}
	return nil
}

func (r *gatewayReconciler) updateGRPCRouteStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.GRPCRoute, new *gatewayv1.GRPCRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("Updating GRPCRoute status", tlsRoute, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) updateBackendTLSPolicyStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.BackendTLSPolicy, new *gatewayv1.BackendTLSPolicy) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("BackendTLSPolicy status", backendTLSPolicy, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return r.Client.Status().Update(ctx, new)
}
