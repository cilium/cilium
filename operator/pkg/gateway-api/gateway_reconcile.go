// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"encoding/pem"
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	translation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *gatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: gateway,
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Reconciling Gateway")

	// Step 1: Retrieve the Gateway
	original := &gatewayv1beta1.Gateway{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return success()
		}
		scopedLog.WithError(err).Error("Unable to get Gateway")
		return fail(err)
	}

	// Ignore deleting Gateway, this can happen when foregroundDeletion is enabled
	// The reconciliation loop will automatically kick off for related Gateway resources.
	if original.GetDeletionTimestamp() != nil {
		scopedLog.Info("Gateway is being deleted, doing nothing")
		return success()
	}

	gw := original.DeepCopy()
	defer func() {
		if err := r.updateStatus(ctx, original, gw); err != nil {
			scopedLog.WithError(err).Error("Unable to update Gateway status")
		}
	}()

	// Step 2: Gather all required information for the ingestion model
	gwc := &gatewayv1beta1.GatewayClass{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gwc); err != nil {
		scopedLog.WithField(gatewayClass, gw.Spec.GatewayClassName).
			WithError(err).
			Error("Unable to get GatewayClass")
		if k8serrors.IsNotFound(err) {
			setGatewayAccepted(gw, false, "GatewayClass does not exist")
			return fail(err)
		}
		setGatewayAccepted(gw, false, "Unable to get GatewayClass")
		return fail(err)
	}

	httpRouteList := &gatewayv1beta1.HTTPRouteList{}
	if err := r.Client.List(ctx, httpRouteList); err != nil {
		scopedLog.WithError(err).Error("Unable to list HTTPRoutes")
		return fail(err)
	}

	tlsRouteList := &gatewayv1alpha2.TLSRouteList{}
	if err := r.Client.List(ctx, tlsRouteList); err != nil {
		scopedLog.WithError(err).Error("Unable to list TLSRoutes")
		return fail(err)
	}

	// TODO(tam): Only list the services used by accepted Routes
	servicesList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, servicesList); err != nil {
		scopedLog.WithError(err).Error("Unable to list Services")
		return fail(err)
	}

	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		scopedLog.WithError(err).Error("Unable to list ReferenceGrants")
		return fail(err)
	}

	httpListeners, tlsListeners := ingestion.GatewayAPI(ingestion.Input{
		GatewayClass:    *gwc,
		Gateway:         *gw,
		HTTPRoutes:      r.filterHTTPRoutesByGateway(ctx, gw, httpRouteList.Items),
		TLSRoutes:       r.filterTLSRoutesByGateway(ctx, gw, tlsRouteList.Items),
		Services:        servicesList.Items,
		ReferenceGrants: grants.Items,
	})

	if err := r.setListenerStatus(ctx, gw, httpRouteList, tlsRouteList); err != nil {
		scopedLog.WithError(err).Error("Unable to set listener status")
		setGatewayAccepted(gw, false, "Unable to set listener status")
		return fail(err)
	}
	setGatewayAccepted(gw, true, "Gateway successfully scheduled")

	// Step 3: Translate the listeners into Cilium model
	cec, svc, ep, err := translation.NewTranslator(r.SecretsNamespace, r.IdleTimeoutSeconds).Translate(&model.Model{HTTP: httpListeners, TLS: tlsListeners})
	if err != nil {
		scopedLog.WithError(err).Error("Unable to translate resources")
		setGatewayAccepted(gw, false, "Unable to translate resources")
		return fail(err)
	}

	if err = r.ensureService(ctx, svc); err != nil {
		scopedLog.WithError(err).Error("Unable to create Service")
		setGatewayAccepted(gw, false, "Unable to create Service resource")
		return fail(err)
	}

	if err = r.ensureEndpoints(ctx, ep); err != nil {
		scopedLog.WithError(err).Error("Unable to ensure Endpoints")
		setGatewayAccepted(gw, false, "Unable to ensure Endpoints resource")
		return fail(err)
	}

	if err = r.ensureEnvoyConfig(ctx, cec); err != nil {
		scopedLog.WithError(err).Error("Unable to ensure CiliumEnvoyConfig")
		setGatewayAccepted(gw, false, "Unable to ensure CEC resource")
		return fail(err)
	}

	// Step 4: Update the status of the Gateway
	if err = r.setAddressStatus(ctx, gw); err != nil {
		scopedLog.WithError(err).Error("Address is not ready")
		setGatewayProgrammed(gw, false, "Address is not ready")
		return fail(err)
	}

	setGatewayProgrammed(gw, true, "Gateway successfully reconciled")
	scopedLog.Info("Successfully reconciled Gateway")
	return success()
}

func (r *gatewayReconciler) ensureService(ctx context.Context, desired *corev1.Service) error {
	existing := &corev1.Service{}
	err := r.Client.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return r.Client.Create(ctx, desired)
		}
		return err
	}

	temp := existing.DeepCopy()
	temp.Spec = desired.Spec
	setMergedLabelsAndAnnotations(temp, desired)

	return r.Client.Patch(ctx, temp, client.MergeFrom(existing))
}

func (r *gatewayReconciler) ensureEndpoints(ctx context.Context, desired *corev1.Endpoints) error {
	existing := &corev1.Endpoints{}
	err := r.Client.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return r.Client.Create(ctx, desired)
		}
		return err
	}

	temp := existing.DeepCopy()
	temp.Subsets = desired.Subsets
	setMergedLabelsAndAnnotations(temp, desired)

	return r.Client.Patch(ctx, temp, client.MergeFrom(existing))
}

func (r *gatewayReconciler) ensureEnvoyConfig(ctx context.Context, desired *ciliumv2.CiliumEnvoyConfig) error {
	existing := &ciliumv2.CiliumEnvoyConfig{}
	err := r.Client.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return r.Client.Create(ctx, desired)
		}
		return err
	}
	temp := existing.DeepCopy()
	temp.Spec = desired.Spec
	setMergedLabelsAndAnnotations(temp, desired)

	return r.Client.Patch(ctx, temp, client.MergeFrom(existing))
}

func (r *gatewayReconciler) updateStatus(ctx context.Context, original *gatewayv1beta1.Gateway, new *gatewayv1beta1.Gateway) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) filterHTTPRoutesByGateway(ctx context.Context, gw *gatewayv1beta1.Gateway, routes []gatewayv1beta1.HTTPRoute) []gatewayv1beta1.HTTPRoute {
	var filtered []gatewayv1beta1.HTTPRoute
	for _, route := range routes {
		if isAccepted(ctx, gw, &route, route.Status.Parents) && isAllowed(ctx, r.Client, gw, &route) && len(computeHosts(gw, route.Spec.Hostnames)) > 0 {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (r *gatewayReconciler) filterHTTPRoutesByListener(ctx context.Context, gw *gatewayv1beta1.Gateway, listener *gatewayv1beta1.Listener, routes []gatewayv1beta1.HTTPRoute) []gatewayv1beta1.HTTPRoute {
	var filtered []gatewayv1beta1.HTTPRoute
	for _, route := range routes {
		if isAccepted(ctx, gw, &route, route.Status.Parents) &&
			isAllowed(ctx, r.Client, gw, &route) &&
			len(computeHostsForListener(listener, route.Spec.Hostnames)) > 0 &&
			parentRefMatched(gw, listener, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func parentRefMatched(gw *gatewayv1beta1.Gateway, listener *gatewayv1beta1.Listener, routeNamespace string, refs []gatewayv1beta1.ParentReference) bool {
	for _, ref := range refs {
		if string(ref.Name) == gw.GetName() && gw.GetNamespace() == helpers.NamespaceDerefOr(ref.Namespace, routeNamespace) {
			if ref.SectionName == nil && ref.Port == nil {
				return true
			}
			var sectionNameCheck = ref.SectionName == nil || *ref.SectionName == listener.Name
			var portCheck = ref.Port == nil || *ref.Port == listener.Port
			if sectionNameCheck && portCheck {
				return true
			}
		}
	}
	return false
}

func (r *gatewayReconciler) filterTLSRoutesByGateway(ctx context.Context, gw *gatewayv1beta1.Gateway, routes []gatewayv1alpha2.TLSRoute) []gatewayv1alpha2.TLSRoute {
	var filtered []gatewayv1alpha2.TLSRoute
	for _, route := range routes {
		if isAccepted(ctx, gw, &route, route.Status.Parents) && isAllowed(ctx, r.Client, gw, &route) && len(computeHosts(gw, route.Spec.Hostnames)) > 0 {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func (r *gatewayReconciler) filterTLSRoutesByListener(ctx context.Context, gw *gatewayv1beta1.Gateway, listener *gatewayv1beta1.Listener, routes []gatewayv1alpha2.TLSRoute) []gatewayv1alpha2.TLSRoute {
	var filtered []gatewayv1alpha2.TLSRoute
	for _, route := range routes {
		if isAccepted(ctx, gw, &route, route.Status.Parents) &&
			isAllowed(ctx, r.Client, gw, &route) &&
			len(computeHostsForListener(listener, route.Spec.Hostnames)) > 0 &&
			parentRefMatched(gw, listener, route.GetNamespace(), route.Spec.ParentRefs) {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func isAccepted(_ context.Context, gw *gatewayv1beta1.Gateway, route metav1.Object, parents []gatewayv1beta1.RouteParentStatus) bool {
	for _, rps := range parents {
		if helpers.NamespaceDerefOr(rps.ParentRef.Namespace, route.GetNamespace()) != gw.GetNamespace() ||
			string(rps.ParentRef.Name) != gw.GetName() {
			continue
		}

		for _, cond := range rps.Conditions {
			if cond.Type == conditionStatusAccepted && cond.Status == metav1.ConditionTrue {
				return true
			}
		}
	}
	return false
}

func (r *gatewayReconciler) setAddressStatus(ctx context.Context, gw *gatewayv1beta1.Gateway) error {
	svcList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, svcList, client.MatchingLabels{
		owningGatewayLabel: gw.GetName(),
	}); err != nil {
		return err
	}

	if len(svcList.Items) == 0 {
		return fmt.Errorf("no service found")
	}

	svc := svcList.Items[0]
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		return fmt.Errorf("load balancer status is not ready")
	}

	var addresses []gatewayv1beta1.GatewayStatusAddress
	for _, s := range svc.Status.LoadBalancer.Ingress {
		if len(s.IP) != 0 {
			addresses = append(addresses, gatewayv1beta1.GatewayStatusAddress{
				Type:  GatewayAddressTypePtr(gatewayv1beta1.IPAddressType),
				Value: s.IP,
			})
		}
		if len(s.Hostname) != 0 {
			addresses = append(addresses, gatewayv1beta1.GatewayStatusAddress{
				Type:  GatewayAddressTypePtr(gatewayv1beta1.HostnameAddressType),
				Value: s.Hostname,
			})
		}
	}

	gw.Status.Addresses = addresses
	return nil
}

func (r *gatewayReconciler) setListenerStatus(ctx context.Context, gw *gatewayv1beta1.Gateway, httpRoutes *gatewayv1beta1.HTTPRouteList, tlsRoutes *gatewayv1alpha2.TLSRouteList) error {
	grants := &gatewayv1beta1.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		return fmt.Errorf("failed to retrieve reference grants: %w", err)
	}

	for _, l := range gw.Spec.Listeners {
		isValid := true

		// SupportedKinds is a required field, so we can't declare it as nil.
		supportedKinds := []gatewayv1beta1.RouteGroupKind{}
		invalidRouteKinds := false
		protoGroup, protoKind := getSupportedGroupKind(l.Protocol)

		if l.AllowedRoutes != nil && len(l.AllowedRoutes.Kinds) != 0 {
			for _, k := range l.AllowedRoutes.Kinds {
				if groupDerefOr(k.Group, gatewayv1beta1.GroupName) == string(*protoGroup) &&
					k.Kind == protoKind {
					supportedKinds = append(supportedKinds, k)
				} else {
					invalidRouteKinds = true
				}
			}
		} else {
			g, k := getSupportedGroupKind(l.Protocol)
			supportedKinds = []gatewayv1beta1.RouteGroupKind{
				{
					Group: g,
					Kind:  k,
				},
			}
		}
		var conds []metav1.Condition
		if invalidRouteKinds {
			conds = append(conds, gatewayListenerInvalidRouteKinds(gw, "Invalid Route Kinds"))
			isValid = false
		} else {
			conds = append(conds, gatewayListenerProgrammedCondition(gw, true, "Listener Programmed"))
			conds = append(conds, gatewayListenerAcceptedCondition(gw, true, "Listener Accepted"))
		}

		if l.TLS != nil {
			for _, cert := range l.TLS.CertificateRefs {
				if !helpers.IsSecret(cert) {
					conds = merge(conds, metav1.Condition{
						Type:               string(gatewayv1beta1.ListenerConditionResolvedRefs),
						Status:             metav1.ConditionFalse,
						Reason:             string(gatewayv1beta1.ListenerReasonInvalidCertificateRef),
						Message:            "Invalid CertificateRef",
						LastTransitionTime: metav1.Now(),
					})
					isValid = false
					break
				}

				if !helpers.IsSecretReferenceAllowed(gw.Namespace, cert, gatewayv1beta1.SchemeGroupVersion.WithKind("Gateway"), grants.Items) {
					conds = merge(conds, metav1.Condition{
						Type:               string(gatewayv1beta1.ListenerConditionResolvedRefs),
						Status:             metav1.ConditionFalse,
						Reason:             string(gatewayv1beta1.ListenerReasonRefNotPermitted),
						Message:            "CertificateRef is not permitted",
						LastTransitionTime: metav1.Now(),
					})
					isValid = false
					break
				}

				if err := validateTLSSecret(ctx, r.Client, helpers.NamespaceDerefOr(cert.Namespace, gw.GetNamespace()), string(cert.Name)); err != nil {
					conds = merge(conds, metav1.Condition{
						Type:               string(gatewayv1beta1.ListenerConditionResolvedRefs),
						Status:             metav1.ConditionFalse,
						Reason:             string(gatewayv1beta1.ListenerReasonInvalidCertificateRef),
						Message:            "Invalid CertificateRef",
						LastTransitionTime: metav1.Now(),
					})
					isValid = false
					break
				}
			}
		}

		var attachedRoutes int32
		if isValid {
			attachedRoutes += int32(len(r.filterHTTPRoutesByListener(ctx, gw, &l, httpRoutes.Items)))
			attachedRoutes += int32(len(r.filterTLSRoutesByListener(ctx, gw, &l, tlsRoutes.Items)))
		}

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
			gw.Status.Listeners = append(gw.Status.Listeners, gatewayv1beta1.ListenerStatus{
				Name:           l.Name,
				SupportedKinds: supportedKinds,
				Conditions:     conds,
				AttachedRoutes: attachedRoutes,
			})
		}
	}

	// filter listener status to only have active listeners
	var newListenersStatus []gatewayv1beta1.ListenerStatus
	for _, ls := range gw.Status.Listeners {
		for _, l := range gw.Spec.Listeners {
			if ls.Name == l.Name {
				newListenersStatus = append(newListenersStatus, ls)
				break
			}
		}
	}
	gw.Status.Listeners = newListenersStatus
	return nil
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
		return fmt.Errorf("invalid certificate")
	}

	if !isValidPemFormat(secret.Data[corev1.TLSPrivateKeyKey]) {
		return fmt.Errorf("invalid private key")
	}
	return nil
}

// isValidPemFormat checks if the given byte array is a valid PEM format.
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
	return isValidPemFormat(rest)
}
