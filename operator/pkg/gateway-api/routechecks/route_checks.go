// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"fmt"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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

func CheckExtensionRefs(input Input, parentRef gatewayv1.ParentReference) (bool, error) {
	extRefInput, ok := input.(ExtensionRefInput)
	if !ok {
		return true, nil
	}

	continueChecks := true
	var incompatibleFilters []string

	for ruleIndex, rule := range input.GetRules() {
		ruleWithExtensionRefs, ok := rule.(extensionRefRule)
		if !ok {
			continue
		}

		refs := ruleWithExtensionRefs.GetExtensionRefs()
		incompatibleFilters = append(incompatibleFilters, duplicateExtProcRefMessages(refs, ruleIndex)...)
		if httpRule, ok := rule.(*HTTPRouteRule); ok {
			if message := httpExtProcOrderViolation(httpRule, ruleIndex); message != "" {
				incompatibleFilters = append(incompatibleFilters, message)
			}
		}

		for _, ref := range refs {
			if !extRefInput.GetExtensionRefFiltersEnabled() {
				input.SetParentCondition(parentRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonInvalidKind),
					Message: "ExtensionRef filters are disabled",
				})
				continueChecks = false
				continue
			}

			if !isExtProcExtensionRef(ref) {
				input.SetParentCondition(parentRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonInvalidKind),
					Message: "Unsupported ExtensionRef kind " + string(ref.Kind),
				})
				continueChecks = false
				continue
			}

			filter := helpers.FindExtProcFilter(extRefInput.GetExtensionRefFilters(), input.GetNamespace(), string(ref.Name))
			if filter == nil {
				input.SetParentCondition(parentRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: "Referenced CiliumEnvoyExtProcFilter does not exist",
				})
				continueChecks = false
				continue
			}

			resolved, err := checkExtProcBackendService(input, parentRef, filter)
			if err != nil {
				return false, err
			}
			if !resolved {
				continueChecks = false
			}
		}
	}

	if len(incompatibleFilters) > 0 {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.RouteReasonIncompatibleFilters),
			Message: helpers.ExtProcConditionMessagePrefix + strings.Join(incompatibleFilters, "; "),
		})
		continueChecks = false
	}

	return continueChecks, nil
}

func isExtProcExtensionRef(ref gatewayv1.LocalObjectReference) bool {
	return string(ref.Group) == v2alpha1.CustomResourceDefinitionGroup && string(ref.Kind) == v2alpha1.CEEPFKindDefinition
}

// duplicateExtProcRefMessages reports rules that reference the same ext_proc
// filter more than once. Envoy aggregates identical ext_proc filters into one
// HTTP filter, so a repeated reference cannot mean what it appears to mean.
func duplicateExtProcRefMessages(refs []gatewayv1.LocalObjectReference, ruleIndex int) []string {
	seen := make(map[string]struct{})
	var messages []string
	for _, ref := range refs {
		if !isExtProcExtensionRef(ref) {
			continue
		}
		key := fmt.Sprintf("%s/%s/%s", ref.Group, ref.Kind, ref.Name)
		if _, exists := seen[key]; exists {
			messages = append(messages, fmt.Sprintf("rule %d references ext_proc filter %q more than once; each filter may be referenced only once per rule", ruleIndex, key))
			continue
		}
		seen[key] = struct{}{}
	}
	return messages
}

// httpExtProcOrderViolation reports a rule that declares an ext_proc filter
// after ExternalAuth. Cilium emits ext_proc ahead of ext_authz in the Envoy
// filter chain, so it cannot honour that declaration order.
func httpExtProcOrderViolation(rule *HTTPRouteRule, ruleIndex int) string {
	externalAuthSeen := false
	for _, filter := range rule.Rule.Filters {
		if filter.Type == gatewayv1.HTTPRouteFilterExternalAuth {
			externalAuthSeen = true
			continue
		}
		if !externalAuthSeen || filter.Type != gatewayv1.HTTPRouteFilterExtensionRef || filter.ExtensionRef == nil || !isExtProcExtensionRef(*filter.ExtensionRef) {
			continue
		}
		return fmt.Sprintf("rule %d declares ext_proc filter %q after ExternalAuth; all ext_proc filters must be declared before ExternalAuth", ruleIndex, filter.ExtensionRef.Name)
	}
	return ""
}

func checkExtProcBackendService(input Input, parentRef gatewayv1.ParentReference, filter *v2alpha1.CiliumEnvoyExtProcFilter) (bool, error) {
	backendNamespace := filter.Namespace
	if filter.Spec.BackendRef.Namespace != nil {
		backendNamespace = *filter.Spec.BackendRef.Namespace
	}
	if !helpers.IsReferenceAllowed(
		filter.Namespace,
		filter.Spec.BackendRef.Name,
		helpers.ExtProcBackendRefNamespace(filter.Spec.BackendRef),
		v2alpha1.SchemeGroupVersion.WithKind(v2alpha1.CEEPFKindDefinition),
		corev1.SchemeGroupVersion.WithKind("Service"),
		input.GetGrants(),
	) {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.RouteReasonRefNotPermitted),
			Message: "CiliumEnvoyExtProcFilter backendRef is not permitted",
		})
		return false, nil
	}

	service := &corev1.Service{}
	if err := input.GetClient().Get(input.GetContext(), client.ObjectKey{Namespace: backendNamespace, Name: filter.Spec.BackendRef.Name}, service); err != nil {
		if !k8serrors.IsNotFound(err) {
			input.Log().Error("Failed to get ext_proc backend Service", logfields.Error, err)
			return false, err
		}
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.RouteReasonBackendNotFound),
			Message: fmt.Sprintf("CiliumEnvoyExtProcFilter backend Service %s/%s does not exist", backendNamespace, filter.Spec.BackendRef.Name),
		})
		return false, nil
	}

	if err := checkServicePort(service, filter.Spec.BackendRef.Port); err != nil {
		input.SetParentCondition(parentRef, metav1.Condition{
			Type:    string(gatewayv1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.RouteReasonBackendNotFound),
			Message: err.Error(),
		})
		return false, nil
	}

	return true, nil
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
	return checkServicePort(svc, int32(*be.Port))
}

func checkServicePort(svc *corev1.Service, port int32) error {
	for _, p := range svc.Spec.Ports {
		if p.Port == port {
			return nil
		}
	}

	return fmt.Errorf("Service port %d could not be resolved for backend %s/%s", port, svc.Namespace, svc.Name)
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

		if sp.SessionName != nil && !isValidCookieName(*sp.SessionName) {
			setUnsupportedValue(input, parentRef, "Session name must be a valid HTTP cookie name")
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

func isValidCookieName(name string) bool {
	return (&http.Cookie{Name: name}).Valid() == nil
}

func setUnsupportedValue(input Input, parentRef gatewayv1.ParentReference, message string) {
	input.SetParentCondition(parentRef, metav1.Condition{
		Type:    string(gatewayv1.RouteConditionAccepted),
		Status:  metav1.ConditionFalse,
		Reason:  string(gatewayv1.RouteReasonUnsupportedValue),
		Message: message,
	})
}
