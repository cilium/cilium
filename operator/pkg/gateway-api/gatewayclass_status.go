// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"cmp"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/pkg/features"
)

const (
	gatewayClassAcceptedMessage = "Valid GatewayClass"
)

var supportedFeatures = features.AllFeatures

var gatewayClassSupportedFeatures = getSupportedFeatures()

// This lists the features we do _not_ support, so that we can skip
// them in the supportedFeatures list in the GatewayClass.
var exemptFeatures = []features.Feature{
	features.HTTPRouteParentRefPortFeature,
	features.MeshConsumerRouteFeature,
	features.BackendTLSPolicySanValidationFeature,
	features.TLSRouteModeTerminateFeature,
	features.GatewayBackendClientCertificateFeature,
	features.GatewayFrontendClientCertificateValidationFeature,
	features.GatewayHTTPSListenerDetectMisdirectedRequestsFeature,
}

// List of Gateway API features supported by Cilium.
// The same should stay in sync with GHA CI in .github/workflows/conformance-gateway-api.yaml
func getSupportedFeatures() []gatewayv1.SupportedFeature {
	for _, feature := range exemptFeatures {
		supportedFeatures.Delete(feature)
	}
	ret := make([]gatewayv1.SupportedFeature, 0, len(supportedFeatures))
	for _, feat := range supportedFeatures.UnsortedList() {
		ret = append(ret, gatewayv1.SupportedFeature{Name: gatewayv1.FeatureName(feat.Name)})
	}
	slices.SortFunc(ret, func(a, b gatewayv1.SupportedFeature) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return ret
}

// setGatewayClassAccepted inserts or updates the Accepted condition
// for the provided GatewayClass.
func setGatewayClassAccepted(gwc *gatewayv1.GatewayClass, accepted bool, reason gatewayv1.GatewayClassConditionReason, msg string) *gatewayv1.GatewayClass {
	gwc.Status.Conditions = merge(gwc.Status.Conditions, gatewayClassAcceptedCondition(gwc, accepted, reason, msg))
	return gwc
}

// setGatewayClassSupportedFeatures adds the supported Gateway API features to the status.
func setGatewayClassSupportedFeatures(gwc *gatewayv1.GatewayClass) *gatewayv1.GatewayClass {
	gwc.Status.SupportedFeatures = gatewayClassSupportedFeatures
	return gwc
}

// gatewayClassAcceptedCondition returns the GatewayClass with Accepted status condition.
func gatewayClassAcceptedCondition(gwc *gatewayv1.GatewayClass, accepted bool, reason gatewayv1.GatewayClassConditionReason, msg string) metav1.Condition {
	status := metav1.ConditionTrue
	if !accepted {
		status = metav1.ConditionFalse
	}

	return metav1.Condition{
		Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
		Status:             status,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: gwc.Generation,
		LastTransitionTime: metav1.Now(),
	}
}
