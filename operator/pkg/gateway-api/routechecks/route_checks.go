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
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
	mcsapicontrollers "sigs.k8s.io/mcs-api/pkg/controllers"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func CheckAgainstCrossNamespaceBackendReferences(input Input) (bool, error) {
	continueChecks := true

	for _, rule := range input.GetRules() {
		for _, be := range rule.GetBackendRefs() {
			ns := helpers.NamespaceDerefOr(be.Namespace, input.GetNamespace())

			if ns != input.GetNamespace() && !helpers.IsBackendReferenceAllowed(input.GetNamespace(), be, input.GetGVK(), input.GetGrants()) {
				// no reference grants, update the status for all the parents
				input.SetAllParentCondition(metav1.Condition{
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

func CheckBackend(input Input) (bool, error) {
	continueChecks := true

	for _, rule := range input.GetRules() {
		for _, be := range rule.GetBackendRefs() {
			if !helpers.IsService(be.BackendObjectReference) && !helpers.IsServiceImport(be.BackendObjectReference) {
				input.SetAllParentCondition(metav1.Condition{
					Type:    string(gatewayv1alpha2.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonInvalidKind),
					Message: "Unsupported backend kind " + string(*be.Kind),
				})

				continueChecks = false
				continue
			}
			if be.BackendObjectReference.Port == nil {
				input.SetAllParentCondition(metav1.Condition{
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

func checkIsExistingService(input Input, objectKey client.ObjectKey) (bool, error) {
	svc := &corev1.Service{}
	if err := input.GetClient().Get(input.GetContext(), objectKey, svc); err != nil {
		if !k8serrors.IsNotFound(err) {
			input.Log().WithError(err).Error("Failed to get Service")
			return false, err
		}
		// Service does not exist, update the status for all the parents
		// The `Accepted` condition on a route only describes whether
		// the route attached successfully to its parent, so no error
		// is returned here, so that the next validation can be run.
		input.SetAllParentCondition(metav1.Condition{
			Type:    string(gatewayv1.RouteConditionResolvedRefs),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.RouteReasonBackendNotFound),
			Message: err.Error(),
		})
	}

	return true, nil
}

func CheckBackendIsExistingService(input Input) (bool, error) {
	continueChecks := true

	for _, rule := range input.GetRules() {
		for _, be := range rule.GetBackendRefs() {
			if !helpers.IsService(be.BackendObjectReference) {
				continue
			}
			ns := helpers.NamespaceDerefOr(be.Namespace, input.GetNamespace())
			continueChecking, err := checkIsExistingService(input, client.ObjectKey{Name: string(be.Name), Namespace: ns})
			continueChecks = continueChecks && continueChecking
			if err != nil {
				return continueChecks, err
			}
		}
	}

	return continueChecks, nil
}

func CheckHasServiceImportSupport(input Input) (bool, error) {
	for _, rule := range input.GetRules() {
		for _, be := range rule.GetBackendRefs() {
			if !helpers.IsServiceImport(be.BackendObjectReference) {
				continue
			}

			if !helpers.HasServiceImportCRD() {
				input.SetAllParentCondition(metav1.Condition{
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

func CheckBackendIsExistingServiceImport(input Input) (bool, error) {
	continueChecks := true

	for _, rule := range input.GetRules() {
		for _, be := range rule.GetBackendRefs() {
			if !helpers.IsServiceImport(be.BackendObjectReference) {
				continue
			}

			ns := helpers.NamespaceDerefOr(be.Namespace, input.GetNamespace())
			svcImport := &mcsapiv1alpha1.ServiceImport{}
			if err := input.GetClient().Get(input.GetContext(), client.ObjectKey{Namespace: ns, Name: string(be.Name)}, svcImport); err != nil {
				if !k8serrors.IsNotFound(err) {
					input.Log().WithError(err).Error("Failed to get ServiceImport")
					return false, err
				}
				// Service Import does not exist, update the status for all the parents
				// The `Accepted` condition on a route only describes whether
				// the route attached successfully to its parent, so no error
				// is returned here, so that the next validation can be run.
				input.SetAllParentCondition(metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: err.Error(),
				})
				continue
			}
			// ServiceImport gateway api support is conditioned by the fact
			// that an actual Service backs it. Other implementations of MCS API
			// are not supported.
			svcName, ok := svcImport.Annotations[mcsapicontrollers.DerivedServiceAnnotation]
			if !ok {
				input.SetAllParentCondition(metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: fmt.Sprintf("%s %s/%s does not have annotation %s", svcImport.Kind, ns, svcImport.Name, mcsapicontrollers.DerivedServiceAnnotation),
				})
				continue
			}
			continueChecking, err := checkIsExistingService(input, client.ObjectKey{Name: svcName, Namespace: ns})
			continueChecks = continueChecks && continueChecking
			if err != nil {
				return continueChecks, err
			}
		}
	}

	return continueChecks, nil
}
