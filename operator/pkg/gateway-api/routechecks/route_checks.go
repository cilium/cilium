// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type sessionPersistenceRule interface {
	GetSessionPersistence() *gatewayv1.SessionPersistence
}

func CheckAgainstCrossNamespaceBackendReferences(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	continueChecks := true

	for _, rule := range input.GetRules() {
		for _, be := range rule.GetBackendRefs() {
			ns := helpers.NamespaceDerefOr(be.Namespace, input.GetNamespace())

			if ns != input.GetNamespace() && !helpers.IsBackendReferenceAllowed(input.GetNamespace(), be, input.GetGVK(), input.GetGrants()) {
				// no reference grants, update the status for all the parents
				input.SetParentCondition(parentRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonRefNotPermitted),
					Message: "Cross namespace references are not allowed",
				})

				continueChecks = false
			}
		}
	}
	return continueChecks, nil
}

func CheckBackend(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	continueChecks := true

	for _, rule := range input.GetRules() {
		for _, be := range rule.GetBackendRefs() {
			if !helpers.IsService(be.BackendObjectReference) && !helpers.IsServiceImport(be.BackendObjectReference) {
				input.SetParentCondition(parentRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonInvalidKind),
					Message: "Unsupported backend kind " + string(*be.Kind),
				})

				continueChecks = false
				continue
			}
			if be.BackendObjectReference.Port == nil {
				input.SetParentCondition(parentRef, metav1.Condition{
					Type:    string(gatewayv1alpha2.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonInvalidKind),
					Message: "Must have port for backend object reference",
				})

				continueChecks = false
				continue
			}
		}
	}

	return continueChecks, nil
}

func CheckHasServiceImportSupport(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	for _, rule := range input.GetRules() {
		for _, be := range rule.GetBackendRefs() {
			if !helpers.IsServiceImport(be.BackendObjectReference) {
				continue
			}

			if !helpers.HasServiceImportSupport(input.GetClient().Scheme()) {
				input.SetParentCondition(parentRef, metav1.Condition{
					Type:   string(gatewayv1.RouteConditionResolvedRefs),
					Status: metav1.ConditionFalse,
					Reason: string(gatewayv1.RouteReasonBackendNotFound),
					Message: "Attempt to reference a ServiceImport backend while " +
						"the corresponding CRD is not installed, " +
						"please restart the cilium-operator if the CRD is already installed",
				})
				return false, nil
			}
			return true, nil
		}
	}

	return true, nil
}

func CheckBackendIsExistingService(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	for _, rule := range input.GetRules() {
		for _, be := range rule.GetBackendRefs() {
			ns := helpers.NamespaceDerefOr(be.Namespace, input.GetNamespace())
			svcName, err := helpers.GetBackendServiceName(input.GetClient(), ns, be.BackendObjectReference)
			if err != nil {
				// Service Import does not exist, update the status for all the parents
				// The `Accepted` condition on a route only describes whether
				// the route attached successfully to its parent, so no error
				// is returned here, so that the next validation can be run.
				input.SetParentCondition(parentRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: err.Error(),
				})
				continue
			}
			svc := &corev1.Service{}
			if err := input.GetClient().Get(input.GetContext(), client.ObjectKey{Name: svcName, Namespace: ns}, svc); err != nil {
				if !k8serrors.IsNotFound(err) {
					input.Log().Error("Failed to get Service", logfields.Error, err)
					return false, err
				}
				// Service does not exist, update the status for all the parents
				// The `Accepted` condition on a route only describes whether
				// the route attached successfully to its parent, so no error
				// is returned here, so that the next validation can be run.
				input.SetParentCondition(parentRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: err.Error(),
				})
				continue
			}

			if err := checkBackendServicePort(svc, be); err != nil {
				input.SetParentCondition(parentRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: err.Error(),
				})
			}
		}
	}

	return true, nil
}

func checkBackendServicePort(svc *corev1.Service, be gatewayv1.BackendRef) error {
	if be.Port == nil {
		return nil
	}

	for _, p := range svc.Spec.Ports {
		if gatewayv1.PortNumber(p.Port) == *be.Port {
			return nil
		}
	}

	return fmt.Errorf("Service port %d could not be resolved for backend %s/%s", *be.Port, svc.Namespace, svc.Name)
}

func CheckSessionPersistence(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	continueChecks := true
	for _, rule := range input.GetRules() {
		sessionRule, ok := rule.(sessionPersistenceRule)
		if !ok {
			continue
		}

		sp := sessionRule.GetSessionPersistence()
		if sp == nil {
			continue
		}

		if helpers.IsGammaService(parentRef) {
			setUnsupportedValue(input, parentRef, "Cilium does not support session persistence for GAMMA routes")
			return false, nil
		}

		if sp.Type != nil && *sp.Type != gatewayv1.CookieBasedSessionPersistence {
			setUnsupportedValue(input, parentRef, "Cilium only supports cookie-based session persistence")
			continueChecks = false
			continue
		}

		if sp.SessionName != nil && *sp.SessionName == "" {
			setUnsupportedValue(input, parentRef, "Session name cannot be explicitly empty")
			continueChecks = false
			continue
		}

		if sp.AbsoluteTimeout != nil {
			setUnsupportedValue(input, parentRef, "Unsupported session persistence field AbsoluteTimeout")
			continueChecks = false
			continue
		}

		if cc := sp.CookieConfig; cc != nil {

			if cc.LifetimeType != nil && *cc.LifetimeType != gatewayv1.SessionCookieLifetimeType {
				setUnsupportedValue(input, parentRef, "Cilium only supports session cookie persistence")
				continueChecks = false
			}
		}
	}

	return continueChecks, nil
}

func setUnsupportedValue(input Input, parentRef gatewayv1.ParentReference, message string) {
	input.SetParentCondition(parentRef, metav1.Condition{
		Type:    string(gatewayv1.RouteConditionAccepted),
		Status:  metav1.ConditionFalse,
		Reason:  string(gatewayv1.RouteReasonUnsupportedValue),
		Message: message,
	})
}
