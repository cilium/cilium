// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policychecks

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func CheckTargetIsExistingService(input Input, ancestorRef gatewayv1.ParentReference, targetFullName types.NamespacedName, sectionName gatewayv1.SectionName) (bool, error) {
	// we loop across this to find the first TargetRef that matches - BackendTLSPolicy
	// currently does not support multiple references to the same Service with different
	// SectionNames, which is the only way we would find _two_ valid targets here.
	// So, we can get away with returning as soon as we find a match for the target
	// Name and Namespace.
	for _, target := range input.GetTargetRefs() {

		if string(target.Name) != targetFullName.Name ||
			input.GetNamespace() != targetFullName.Namespace ||
			*target.SectionName != sectionName {
			// Not this target, try the next one
			continue
		}

		// This should never happen, because we should be screening non-services when building the list
		// of targets (that we shource targetFullName from)
		if !helpers.IsServiceTargetRef(target) {
			input.SetAncestorCondition(ancestorRef, metav1.Condition{
				Type:    string(gatewayv1.PolicyConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.PolicyReasonInvalid),
				Message: fmt.Sprintf("TargetRef is not a Service %s", targetFullName),
			})
			input.SetAncestorCondition(ancestorRef, metav1.Condition{
				Type:    string(gatewayv1.RouteConditionResolvedRefs),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.RouteReasonBackendNotFound),
				Message: fmt.Sprintf("TargetRef is not a Service %s", targetFullName),
			})
			return false, fmt.Errorf("TargetRef is not a Service %s", targetFullName)
		}

		// We checked that the Service exists before calling this check, along with the sectionName,
		// so we can assume that it does.

		// Check that specific Service exists
		// (For BackendTLSPolicy, the Policy must be in the same namespace as the Service)
		obj := &corev1.Service{}
		err := input.GetClient().Get(input.GetContext(), targetFullName, obj)
		if err != nil {
			if !k8serrors.IsNotFound(err) {
				// if it is not just a not found error, we should return the error as something is bad
				return false, fmt.Errorf("error while checking Backend Service: %w", err)
			}
			// Otherwise, we can just set resolvedRefs to false.
			input.SetAncestorCondition(ancestorRef, metav1.Condition{
				Type:    string(gatewayv1.PolicyConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.PolicyReasonInvalid),
				Message: fmt.Sprintf("TargetRef does not exist: %s", targetFullName),
			})
			input.SetAncestorCondition(ancestorRef, metav1.Condition{
				Type:    string(gatewayv1.RouteConditionResolvedRefs),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.RouteReasonBackendNotFound),
				Message: fmt.Sprintf("TargetRef does not exist: %s", targetFullName),
			})
			return false, fmt.Errorf("TargetRef does not exist: %s", targetFullName)
		}

		if target.SectionName != nil {
			for _, port := range obj.Spec.Ports {
				if port.Name == string(*target.SectionName) {
					// There's a section name set, and we match it, we accept this one.
					return true, nil
				}
			}
			// There's a sectionName set, but we didn't match it, so return an error
			input.SetAncestorCondition(ancestorRef, metav1.Condition{
				Type:    string(gatewayv1.PolicyConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.PolicyReasonInvalid),
				Message: fmt.Sprintf("Could not find named port %s on Service %s", *target.SectionName, targetFullName),
			})
			input.SetAncestorCondition(ancestorRef, metav1.Condition{
				Type:    string(gatewayv1.RouteConditionResolvedRefs),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.RouteReasonBackendNotFound),
				Message: fmt.Sprintf("Could not find named port %s on Service %s", *target.SectionName, targetFullName),
			})
			return false, fmt.Errorf("Could not find named port %s on Service %s", *target.SectionName, targetFullName)
		}
		// We passed the checks, so we can return no error.
		return true, nil
	}
	// In this case, there was no match, so the target is not valid for this BackendTLSPolicy
	// Again, this should not happen because we should be filtering this out before this stage.
	return false, fmt.Errorf("Could not find a match for target %s", targetFullName)
}
