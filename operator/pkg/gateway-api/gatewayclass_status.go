// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"cmp"
	"slices"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/pkg/features"
)

const (
	gatewayClassAcceptedMessage    = "Valid GatewayClass"
	gatewayClassNotAcceptedMessage = "Invalid GatewayClass"
)

var supportedFeatures = features.AllFeatures

var gatewayClassSupportedFeatures = getSupportedFeatures()

var exemptFeatures = []features.Feature{
	features.HTTPRouteParentRefPortFeature,
	features.MeshConsumerRouteFeature,
}

// List of Gateway API features supported by Cilium.
// The same should stay in sync with GHA CI in .github/workflows/conformance-gateway-api.yaml
func getSupportedFeatures() []gatewayv1.SupportedFeature {
	for _, feature := range exemptFeatures {
		supportedFeatures.Delete(feature)
	}
	ret := []gatewayv1.SupportedFeature{}
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
func setGatewayClassAccepted(gwc *gatewayv1.GatewayClass, accepted bool) *gatewayv1.GatewayClass {
	gwc.Status.Conditions = merge(gwc.Status.Conditions, gatewayClassAcceptedCondition(gwc, accepted))
	return gwc
}

// setGatewayClassSupportedFeatures adds the supported Gateway API features to the status.
func setGatewayClassSupportedFeatures(gwc *gatewayv1.GatewayClass) *gatewayv1.GatewayClass {
	gwc.Status.SupportedFeatures = gatewayClassSupportedFeatures
	return gwc
}

// gatewayClassAcceptedCondition returns the GatewayClass with Accepted status condition.
// TODO(tam): Update GatewayClassReasonInvalidParameters message when parameter support is added.
func gatewayClassAcceptedCondition(gwc *gatewayv1.GatewayClass, accepted bool) metav1.Condition {
	switch accepted {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.GatewayClassReasonAccepted),
			Message:            gatewayClassAcceptedMessage,
			ObservedGeneration: gwc.Generation,
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1.GatewayClassReasonInvalidParameters),
			Message:            gatewayClassNotAcceptedMessage,
			ObservedGeneration: gwc.Generation,
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}
