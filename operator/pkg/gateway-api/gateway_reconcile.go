// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
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
	setGatewayScheduled(gw, true, "Gateway successfully scheduled")

	// Step 2: Gather all required information for the ingestion model
	gwc := &gatewayv1beta1.GatewayClass{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gwc); err != nil {
		scopedLog.WithField(gatewayClass, gw.Spec.GatewayClassName).
			WithError(err).
			Error("Unable to get GatewayClass")
		if k8serrors.IsNotFound(err) {
			setGatewayScheduled(gw, false, "GatewayClass does not exist")
			return fail(err)
		}
		setGatewayScheduled(gw, false, "Unable to get GatewayClass")
		return fail(err)
	}

	routeList := &gatewayv1beta1.HTTPRouteList{}
	if err := r.Client.List(ctx, routeList); err != nil {
		scopedLog.WithError(err).Error("Unable to list HTTPRoutes")
		return fail(err)
	}

	// TODO(tam): Only list the services used by accepted HTTPRoutes
	servicesList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, servicesList); err != nil {
		scopedLog.WithError(err).Error("Unable to list Services")
		return fail(err)
	}

	grants := &gatewayv1alpha2.ReferenceGrantList{}
	if err := r.Client.List(ctx, grants); err != nil {
		scopedLog.WithError(err).Error("Unable to list ReferenceGrants")
		return fail(err)
	}

	routes := r.filterRoutesByGateway(ctx, gw, routeList.Items)
	listeners := ingestion.GatewayAPI(ingestion.Input{
		GatewayClass:    *gwc,
		Gateway:         *gw,
		HTTPRoutes:      routes,
		Services:        servicesList.Items,
		ReferenceGrants: grants.Items,
	})

	// Step 3: Translate the listeners into Cilium model
	cec, svc, ep, err := translation.NewTranslator(r.SecretsNamespace).Translate(&model.Model{HTTP: listeners})
	if err != nil {
		scopedLog.WithError(err).Error("Unable to translate resources")
		setGatewayScheduled(gw, false, "Unable to translate resources")
		return fail(err)
	}

	if err = r.ensureService(ctx, svc); err != nil {
		scopedLog.WithError(err).Error("Unable to create Service")
		setGatewayScheduled(gw, false, "Unable to create Service resource")
		return fail(err)
	}

	if err = r.ensureEndpoints(ctx, ep); err != nil {
		scopedLog.WithError(err).Error("Unable to ensure Endpoints")
		setGatewayScheduled(gw, false, "Unable to ensure Endpoints resource")
		return fail(err)
	}

	if err = r.ensureEnvoyConfig(ctx, cec); err != nil {
		scopedLog.WithError(err).Error("Unable to ensure CiliumEnvoyConfig")
		setGatewayScheduled(gw, false, "Unable to ensure CEC resource")
		return fail(err)
	}

	// Step 4: Update the status of the Gateway
	if err = r.setAddressStatus(ctx, gw); err != nil {
		scopedLog.WithError(err).Error("Address is not ready")
		setGatewayReady(gw, false, "Address is not ready")
		return fail(err)
	}

	if err = r.setListenerStatus(ctx, gw); err != nil {
		scopedLog.WithError(err).Error("Unable to set listener status")
		setGatewayReady(gw, false, "Unable to set listener status")
		return fail(err)
	}

	setGatewayReady(gw, true, "Gateway successfully reconciled")
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
	temp.SetAnnotations(desired.GetAnnotations())
	temp.SetLabels(desired.GetLabels())

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
	temp.SetAnnotations(desired.GetAnnotations())
	temp.SetLabels(desired.GetLabels())

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
	temp.SetAnnotations(desired.GetAnnotations())
	temp.SetLabels(desired.GetLabels())

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

func (r *gatewayReconciler) filterRoutesByGateway(ctx context.Context, gw *gatewayv1beta1.Gateway, routes []gatewayv1beta1.HTTPRoute) []gatewayv1beta1.HTTPRoute {
	var filtered []gatewayv1beta1.HTTPRoute
	for _, route := range routes {
		if isAccepted(ctx, gw, route) && isAllowed(ctx, r.Client, gw, &route) && len(computeHosts(gw, &route)) > 0 {
			filtered = append(filtered, route)
		}
	}
	return filtered
}

func isAccepted(_ context.Context, gw *gatewayv1beta1.Gateway, route gatewayv1beta1.HTTPRoute) bool {
	for _, rps := range route.Status.RouteStatus.Parents {
		if namespaceDerefOr(rps.ParentRef.Namespace, route.GetNamespace()) != gw.GetNamespace() ||
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

	var addresses []gatewayv1beta1.GatewayAddress
	for _, s := range svc.Status.LoadBalancer.Ingress {
		if len(s.IP) != 0 {
			addresses = append(addresses, gatewayv1beta1.GatewayAddress{
				Type:  GatewayAddressTypePtr(gatewayv1beta1.IPAddressType),
				Value: s.IP,
			})
		}
		if len(s.Hostname) != 0 {
			addresses = append(addresses, gatewayv1beta1.GatewayAddress{
				Type:  GatewayAddressTypePtr(gatewayv1beta1.HostnameAddressType),
				Value: s.Hostname,
			})
		}
	}

	gw.Status.Addresses = addresses
	return nil
}

func (r *gatewayReconciler) setListenerStatus(ctx context.Context, gw *gatewayv1beta1.Gateway) error {
	for _, l := range gw.Spec.Listeners {
		cond := gatewayListenerReadyCondition(gw, true, "Listener Ready")
		if l.TLS != nil {
			for _, cert := range l.TLS.CertificateRefs {
				if !IsSecret(cert) {
					continue
				}

				allowed, err := isReferenceAllowed(ctx, r.Client, gw, cert)
				if err != nil {
					return err
				}

				if !allowed {
					cond = metav1.Condition{
						Type:               string(gatewayv1beta1.ListenerConditionResolvedRefs),
						Status:             metav1.ConditionFalse,
						Reason:             string(gatewayv1beta1.ListenerReasonRefNotPermitted),
						Message:            "CertificateRef is not permitted",
						LastTransitionTime: metav1.Now(),
					}
					break
				}

				secret := &corev1.Secret{}
				if err := r.Client.Get(ctx, client.ObjectKey{
					Namespace: namespaceDerefOr(cert.Namespace, gw.GetNamespace()),
					Name:      string(cert.Name),
				}, secret); err != nil {
					if k8serrors.IsNotFound(err) {
						cond = metav1.Condition{
							Type:               string(gatewayv1beta1.ListenerConditionResolvedRefs),
							Status:             metav1.ConditionFalse,
							Reason:             string(gatewayv1beta1.ListenerReasonInvalidCertificateRef),
							Message:            err.Error(),
							LastTransitionTime: metav1.Now(),
						}
						break
					}
					return err
				}
			}
		}

		found := false
		for i := range gw.Status.Listeners {
			if l.Name == gw.Status.Listeners[i].Name {
				found = true
				gw.Status.Listeners[i].Conditions = []metav1.Condition{cond}
				break
			}
		}
		if !found {
			gw.Status.Listeners = append(gw.Status.Listeners, gatewayv1beta1.ListenerStatus{
				Name: l.Name,
				SupportedKinds: []gatewayv1beta1.RouteGroupKind{
					{
						Group: GroupPtr(gatewayv1beta1.GroupName),
						Kind:  getSupportedKind(l.Protocol),
					},
				},
				Conditions: []metav1.Condition{cond},
			})
		}
	}
	return nil
}

func isReferenceAllowed(ctx context.Context, c client.Client, gw *gatewayv1beta1.Gateway, cert gatewayv1beta1.SecretObjectReference) (bool, error) {
	// Secret is in the same namespace as the Gateway
	if cert.Namespace == nil || string(*cert.Namespace) == gw.GetNamespace() {
		return true, nil
	}

	// check if this cert is allowed to be used by this gateway
	grants := &gatewayv1alpha2.ReferenceGrantList{}
	if err := c.List(ctx, grants, client.InNamespace(*cert.Namespace)); err != nil {
		return false, err
	}

	for _, g := range grants.Items {
		for _, from := range g.Spec.From {
			if from.Group == gatewayv1beta1.GroupName &&
				from.Kind == kindGateway && (string)(from.Namespace) == gw.GetNamespace() {
				for _, to := range g.Spec.To {
					if to.Group == corev1.GroupName && to.Kind == kindSecret &&
						(to.Name == nil || string(*to.Name) == string(cert.Name)) {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}
