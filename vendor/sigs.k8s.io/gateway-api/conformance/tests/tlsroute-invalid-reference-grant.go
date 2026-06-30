/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tests

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, TLSRouteInvalidReferenceGrant)
}

var TLSRouteInvalidReferenceGrant = confsuite.ConformanceTest{
	ShortName:   "TLSRouteInvalidReferenceGrant",
	Description: "A single TLSRoute in the gateway-conformance-infra namespace, with a backendRef in another namespace without valid ReferenceGrant, should have the ResolvedRefs condition set to False",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTLSRoute,
		features.SupportReferenceGrant,
	},
	Manifests: []string{"tests/tlsroute-invalid-reference-grant.yaml"},
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		routeNN := types.NamespacedName{Name: confsuite.InfrastructureGatewayName, Namespace: confsuite.InfrastructureNamespace}
		gwNN := types.NamespacedName{Name: "gateway-tlsroute-referencegrant", Namespace: confsuite.InfrastructureNamespace}

		kubernetes.GatewayAndTLSRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		t.Run("TLSRoute with BackendRef in another namespace and no ReferenceGrant covering the Service has a ResolvedRefs Condition with status False and Reason RefNotPermitted", func(t *testing.T) {
			resolvedRefsCond := metav1.Condition{
				Type:   string(v1.RouteConditionResolvedRefs),
				Status: metav1.ConditionFalse,
				Reason: string(v1.RouteReasonRefNotPermitted),
			}

			kubernetes.TLSRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, resolvedRefsCond)
		})
	},
}
