// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	"github.com/cilium/cilium/pkg/annotation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
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
		if k8serrors.IsNotFound(err) {
			scopedLog.InfoContext(ctx, "GatewayClass no longer exists, cleaning up previously managed resources",
				gatewayClass, gw.Spec.GatewayClassName)

			if err := r.cleanupOwnedResources(ctx, gw); err != nil {
				scopedLog.ErrorContext(ctx, "Unable to cleanup managed Gateway resources", logfields.Error, err)
				return controllerruntime.Fail(err)
			}

			return controllerruntime.Success()
		}
		scopedLog.ErrorContext(ctx, "Unable to get GatewayClass",
			gatewayClass, gw.Spec.GatewayClassName,
			logfields.Error, err)
		// Doing nothing till the GatewayClass is available and matching controller name
		return controllerruntime.Success()
	}

	if string(gwc.Spec.ControllerName) != r.controllerName {
		scopedLog.InfoContext(ctx, "GatewayClass does not have matching controller name, cleaning up previously managed resources",
			gatewayClass, gw.Spec.GatewayClassName,
			logfields.Controller, gwc.Spec.ControllerName)
		if err := r.cleanupOwnedResources(ctx, gw); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to cleanup managed Gateway resources", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
		return controllerruntime.Success()
	}

	// At this point, the GatewayClass is managed by Cilium, so Gateway-level validations are safe to run.
	if ref := gw.Spec.Infrastructure; ref != nil && ref.ParametersRef != nil {
		setGatewayAccepted(gw, false, "Invalid Gateway parameters: spec.infrastructure.parametersRef is not supported", gatewayv1.GatewayReasonInvalidParameters)
		setGatewayProgrammed(gw, metav1.ConditionUnknown, "Waiting for Accepted condition to be True", gatewayv1.GatewayReasonPending)
		return r.handleReconcileErrorWithStatus(ctx, errors.New("Invalid Gateway"), original, gw)
	}

	if ref := gwc.Spec.ParametersRef; ref != nil {
		if !isParameterRefSupported(ref) {
			setGatewayAccepted(gw, false, "Invalid GatewayClass parameters: spec.parametersRef.kind must be CiliumGatewayClassConfig", gatewayv1.GatewayReasonInvalidParameters)
			setGatewayProgrammed(gw, metav1.ConditionUnknown, "Waiting for Accepted condition to be True", gatewayv1.GatewayReasonPending)
			return r.handleReconcileErrorWithStatus(ctx, errors.New("Invalid GatewayClass"), original, gw)
		}

		if !hasNamespacedName(ref) {
			setGatewayAccepted(gw, false, "Invalid GatewayClass parametersRef: both name and namespace are required", gatewayv1.GatewayReasonInvalidParameters)
			setGatewayProgrammed(gw, metav1.ConditionUnknown, "Waiting for Accepted condition to be True", gatewayv1.GatewayReasonPending)
			return r.handleReconcileErrorWithStatus(ctx, errors.New("Invalid GatewayClass"), original, gw)
		}
	}

	if err := r.gatewayAddressStatusManager.VerifyGatewayStaticAddresses(gw); err != nil {
		scopedLog.ErrorContext(ctx, "Unsupported Gateway address", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unsupported Gateway address, "+err.Error(), gatewayv1.GatewayReasonUnsupportedAddress)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Address is not ready", gatewayv1.GatewayReasonListenersNotReady)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	inputs, err := r.inputLoader.Load(ctx, scopedLog, gw, gwc)
	if err != nil {
		scopedLog.ErrorContext(ctx, "Unable to load translation inputs", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	if gw.Spec.Infrastructure != nil && gw.Spec.Infrastructure.Annotations[annotation.LBIPAMIPKeyAlias] != "" {
		scopedLog.WarnContext(ctx, fmt.Sprintf("DEPRECATED: The Gateway <%s/%s> is setting an IP address using the infrastructure annotations <%s>."+
			" These should be set using the spec.addresses field in Gateway objects instead."+
			" At a future date this annotation will be removed if no spec.addresses are set.", gw.GetNamespace(), gw.GetName(), annotation.LBIPAMIPKeyAlias))
	}

	if err := r.routeStatusManager.SetRouteStatuses(ctx, scopedLog, RouteStatusInputs{
		HTTPRoutes:      inputs.HTTPRoutes,
		TLSRoutes:       inputs.TLSRoutes,
		GRPCRoutes:      inputs.GRPCRoutes,
		TCPRoutes:       inputs.TCPRoutes,
		UDPRoutes:       inputs.UDPRoutes,
		ReferenceGrants: inputs.ReferenceGrants,
	}); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update route status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	// Attached*Routes() relies on route status parents populated by the status
	// update helpers above, so it must only be used after route status has been
	// computed for this reconciliation.

	btlspStatusMap, err := r.backendTLSPolicyStatusManager.SetBackendTLSPolicyStatuses(
		ctx,
		scopedLog,
		req.NamespacedName,
		inputs.BackendTLSPolicies,
		inputs.AttachedHTTPRoutes(gw),
	)
	if err != nil {
		scopedLog.ErrorContext(ctx, "Unable to update BackendTLSPolicy Status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	listenerStatusResult, err := r.listenerStatusManager.SetListenerStatuses(ctx, gw, ListenerStatusInputs{
		MergedListeners:        inputs.MergedListeners,
		Namespaces:             inputs.Namespaces,
		AttachedListenerSets:   inputs.AttachedListenerSets,
		DisallowedListenerSets: inputs.DisallowedListenerSets,
		HTTPRoutes:             inputs.HTTPRoutes,
		TLSRoutes:              inputs.TLSRoutes,
		GRPCRoutes:             inputs.GRPCRoutes,
		TCPRoutes:              inputs.TCPRoutes,
		UDPRoutes:              inputs.UDPRoutes,
		ReferenceGrants:        inputs.ReferenceGrants,
	})
	if err != nil {
		scopedLog.ErrorContext(ctx, "Unable to set listener status", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to set listener status", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to set listener status", gatewayv1.GatewayReasonListenersNotValid)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	switch listenerStatusResult.GatewayStatus {
	case ListenersStatusNoneValid:
		err := fmt.Errorf("No Accepted Listeners for Gateway")
		scopedLog.ErrorContext(ctx, "No Accepted Listeners for Gateway", logfields.Error, err)
		setGatewayAccepted(gw, false, "No Accepted Listeners", gatewayv1.GatewayReasonListenersNotValid)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "No Accepted Listeners", gatewayv1.GatewayReasonListenersNotValid)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	case ListenersStatusValidWithUnsupportedProtocol:
		setGatewayAccepted(gw, true, "Gateway has unsupported listeners", gatewayv1.GatewayReasonListenersNotValid)
	case ListenersStatusSomeInvalid, ListenersStatusAllValid:
		setGatewayAccepted(gw, true, "Gateway successfully scheduled", gatewayv1.GatewayReasonAccepted)
	}

	// Step 3: Ingest loaded and validated resources into internal model
	m := ingestion.GatewayAPI(scopedLog, ingestion.Input{
		GatewayClass:        *gwc,
		GatewayClassConfig:  inputs.GatewayClassConfig,
		Gateway:             *gw,
		HTTPRoutes:          inputs.AttachedHTTPRoutes(gw),
		TLSRoutes:           inputs.AttachedTLSRoutes(gw),
		GRPCRoutes:          inputs.AttachedGRPCRoutes(gw),
		TCPRoutes:           inputs.AttachedTCPRoutes(gw),
		UDPRoutes:           inputs.AttachedUDPRoutes(gw),
		Services:            inputs.Services,
		ServiceImports:      inputs.ServiceImports,
		ReferenceGrants:     inputs.ReferenceGrants,
		BackendTLSPolicyMap: btlspStatusMap,
		MergedListeners:     listenerStatusResult.MergedAndValidListeners,
	})

	// Step 4: Translate the listeners into Cilium model
	cec, svc, eps, err := r.translator.Translate(m)
	if err != nil {
		scopedLog.ErrorContext(ctx, "Unable to translate resources", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to translate resources", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to translate resources", gatewayv1.GatewayReasonListenersNotValid)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err = r.ensureService(ctx, svc); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to create Service", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to create Service resource", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to create Service resource", gatewayv1.GatewayReasonNoResources)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err = r.reconcileEndpointSlices(ctx, gw, svc, eps); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to reconcile EndpointSlices", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to reconcile EndpointSlices", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to reconcile EndpointSlices", gatewayv1.GatewayReasonNoResources)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err = r.ensureEnvoyConfig(ctx, gw, cec); err != nil {
		scopedLog.ErrorContext(ctx, "Unable to ensure CiliumEnvoyConfig", logfields.Error, err)
		setGatewayAccepted(gw, false, "Unable to ensure CEC resource", gatewayv1.GatewayReasonNoResources)
		setGatewayProgrammed(gw, metav1.ConditionFalse, "Unable to create CEC resource", gatewayv1.GatewayReasonNoResources)
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	// Step 5: Update the status of the Gateway
	if err = r.gatewayAddressStatusManager.SetAddressStatus(ctx, gw); err != nil {
		return r.handleReconcileErrorWithStatus(ctx, err, original, gw)
	}

	if err = r.gatewayAddressStatusManager.SetStaticAddressStatus(ctx, gw); err != nil {
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

// ensureEndpointSlice creates or updates a managed frontend EndpointSlice.
// Endpoints and the numeric Ports[0].Port are owned by endpointSliceReconciler
// once it has populated Endpoints; this avoids a write-fight between the two.
func (r *gatewayReconciler) ensureEndpointSlice(ctx context.Context, desired *discoveryv1.EndpointSlice) error {
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      desired.Name,
			Namespace: desired.Namespace,
		},
	}
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, eps, func() error {
		if eps.ResourceVersion == "" {
			eps.AddressType = desired.AddressType
			eps.Endpoints = desired.Endpoints
			eps.Ports = desired.Ports
		} else {
			resolved := len(eps.Endpoints) > 0
			eps.Ports = mergeEndpointPorts(eps.Ports, desired.Ports, resolved)
		}
		eps.OwnerReferences = desired.OwnerReferences
		setMergedLabelsAndAnnotations(eps, desired)
		return nil
	})
	return err
}

// mergeEndpointPorts takes Name and Protocol from desired; the numeric Port
// is kept from existing when preservePort is true (owned by
// endpointSliceReconciler), otherwise taken from desired.
func mergeEndpointPorts(existing, desired []discoveryv1.EndpointPort, preservePort bool) []discoveryv1.EndpointPort {
	if len(existing) != len(desired) {
		return desired
	}
	out := make([]discoveryv1.EndpointPort, len(desired))
	for i := range desired {
		out[i] = desired[i]
		if preservePort && existing[i].Port != nil {
			out[i].Port = existing[i].Port
		}
	}
	return out
}

func (r *gatewayReconciler) ensureEnvoyConfig(ctx context.Context, gw *gatewayv1.Gateway, desired *ciliumv2.CiliumEnvoyConfig) error {
	if desired == nil {
		// No Envoy config is needed (e.g. the Gateway only has L4 TCP/UDP
		// Routes attached). Delete any CiliumEnvoyConfig left over from a
		// previous state where HTTP/TLS listeners were configured.
		return r.ensureOwnedEnvoyConfigDeleted(ctx, gw)
	}
	cec := desired.DeepCopy()
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, cec, func() error {
		cec.Spec = desired.Spec
		setMergedLabelsAndAnnotations(cec, desired)
		return nil
	})
	return err
}

// reconcileEndpointSlices applies the desired EndpointSlices and deletes
// stale ones owned by the Gateway. Endpoints are populated later by
// endpointSliceReconciler from the backend Service's own EndpointSlices.
func (r *gatewayReconciler) reconcileEndpointSlices(ctx context.Context, gw *gatewayv1.Gateway, svc *corev1.Service, desired []*discoveryv1.EndpointSlice) error {
	desired = r.filterEndpointSlicesByBackendFamilies(ctx, desired)

	desiredByName := make(map[string]*discoveryv1.EndpointSlice, len(desired))
	for _, d := range desired {
		desiredByName[d.Name] = d
		if err := r.ensureEndpointSlice(ctx, d); err != nil {
			return err
		}
	}

	if svc == nil {
		return nil
	}

	existing := &discoveryv1.EndpointSliceList{}
	if err := r.Client.List(
		ctx, existing,
		client.InNamespace(gw.Namespace),
		client.MatchingLabels{
			gatewayApiTranslation.EndpointSliceServiceNameLabel: svc.Name,
			gatewayApiTranslation.EndpointSliceManagedByLabel:   gatewayApiTranslation.EndpointSliceManagedByValue,
		},
	); err != nil {
		return fmt.Errorf("failed to list managed EndpointSlices: %w", err)
	}

	for i := range existing.Items {
		eps := existing.Items[i]
		if !metav1.IsControlledBy(&eps, gw) {
			continue
		}
		if _, ok := desiredByName[eps.Name]; ok {
			continue
		}
		if err := client.IgnoreNotFound(r.Client.Delete(ctx, &eps)); err != nil {
			return fmt.Errorf("failed to delete stale EndpointSlice %s/%s: %w", eps.Namespace, eps.Name, err)
		}
	}

	return nil
}

// filterEndpointSlicesByBackendFamilies drops slices whose AddressType is not
// in the referenced backend Service's IPFamilies, mirroring how
// kube-controller-manager only emits slices for supported families. Slices
// are kept when the backend Service is missing or its IPFamilies is unset so
// the next reconcile can correct them.
func (r *gatewayReconciler) filterEndpointSlicesByBackendFamilies(ctx context.Context, desired []*discoveryv1.EndpointSlice) []*discoveryv1.EndpointSlice {
	type backendKey struct{ ns, name string }
	cache := map[backendKey]map[corev1.IPFamily]struct{}{}

	out := make([]*discoveryv1.EndpointSlice, 0, len(desired))
	for _, s := range desired {
		ref := s.Annotations[gatewayApiTranslation.BackendServiceAnnotation]
		ns, name, ok := strings.Cut(ref, "/")
		if !ok || ns == "" || name == "" {
			out = append(out, s)
			continue
		}
		key := backendKey{ns, name}
		fams, cached := cache[key]
		if !cached {
			be := &corev1.Service{}
			if err := r.Client.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, be); err != nil {
				cache[key] = nil
				out = append(out, s)
				continue
			}
			fams = make(map[corev1.IPFamily]struct{}, len(be.Spec.IPFamilies))
			for _, f := range be.Spec.IPFamilies {
				fams[f] = struct{}{}
			}
			cache[key] = fams
		}
		if len(fams) == 0 {
			out = append(out, s)
			continue
		}
		var want corev1.IPFamily
		switch s.AddressType {
		case discoveryv1.AddressTypeIPv4:
			want = corev1.IPv4Protocol
		case discoveryv1.AddressTypeIPv6:
			want = corev1.IPv6Protocol
		default:
			out = append(out, s)
			continue
		}
		if _, ok := fams[want]; ok {
			out = append(out, s)
		}
	}
	return out
}

func (r *gatewayReconciler) cleanupOwnedResources(ctx context.Context, gw *gatewayv1.Gateway) error {
	if err := r.ensureOwnedServiceDeleted(ctx, gw); err != nil {
		return err
	}
	if err := r.ensureOwnedEndpointSlicesDeleted(ctx, gw); err != nil {
		return err
	}
	if err := r.ensureOwnedEnvoyConfigDeleted(ctx, gw); err != nil {
		return err
	}
	return nil
}

func (r *gatewayReconciler) ensureOwnedServiceDeleted(ctx context.Context, gw *gatewayv1.Gateway) error {
	svc := &corev1.Service{}
	key := types.NamespacedName{
		Namespace: gw.Namespace,
		Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gw.Name),
	}

	if err := r.Client.Get(ctx, key, svc); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(svc, gw) {
		return nil
	}

	return client.IgnoreNotFound(r.Client.Delete(ctx, svc))
}

func (r *gatewayReconciler) ensureOwnedEndpointSlicesDeleted(ctx context.Context, gw *gatewayv1.Gateway) error {
	eps := &discoveryv1.EndpointSliceList{}
	matchingLabels := client.MatchingLabels{
		gatewayApiTranslation.EndpointSliceServiceNameLabel: shortener.ShortenK8sResourceName(
			gatewayApiTranslation.CiliumGatewayPrefix + gw.Name,
		),
	}

	if err := r.Client.List(ctx, eps, client.InNamespace(gw.Namespace), matchingLabels); err != nil {
		return client.IgnoreNotFound(err)
	}

	for _, ep := range eps.Items {
		if !metav1.IsControlledBy(&ep, gw) {
			continue
		}
		if err := client.IgnoreNotFound(r.Client.Delete(ctx, &ep)); err != nil {
			return err
		}
	}

	return nil
}

func (r *gatewayReconciler) ensureOwnedEnvoyConfigDeleted(ctx context.Context, gw *gatewayv1.Gateway) error {
	cec := &ciliumv2.CiliumEnvoyConfig{}
	key := types.NamespacedName{
		Namespace: gw.Namespace,
		Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gw.Name),
	}

	if err := r.Client.Get(ctx, key, cec); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(cec, gw) {
		return nil
	}

	return client.IgnoreNotFound(r.Client.Delete(ctx, cec))
}

func (r *gatewayReconciler) updateStatus(ctx context.Context, original *gatewayv1.Gateway, new *gatewayv1.Gateway) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) handleReconcileErrorWithStatus(ctx context.Context, reconcileErr error, original *gatewayv1.Gateway, modified *gatewayv1.Gateway) (ctrl.Result, error) {
	if err := r.updateStatus(ctx, original, modified); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update Gateway status while handling the reconcile error: %w: %w", reconcileErr, err))
	}

	return controllerruntime.Fail(reconcileErr)
}
