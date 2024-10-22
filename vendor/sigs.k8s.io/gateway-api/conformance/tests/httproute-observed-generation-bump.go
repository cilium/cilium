/*
Copyright 2022 The Kubernetes Authors.

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
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteObservedGenerationBump)
}

var HTTPRouteObservedGenerationBump = suite.ConformanceTest{
	ShortName:   "HTTPRouteObservedGenerationBump",
	Description: "A HTTPRoute in the gateway-conformance-infra namespace should update the observedGeneration in all of it's Status.Conditions after an update to the spec",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/httproute-observed-generation-bump.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		routeNN := types.NamespacedName{Name: "observed-generation-bump", Namespace: "gateway-conformance-infra"}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}

		t.Run("observedGeneration should increment", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), suite.TimeoutConfig.LatestObservedGenerationSet)
			defer cancel()

			namespaces := []string{"gateway-conformance-infra"}
			kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, namespaces)

			original := &v1.HTTPRoute{}
			err := suite.Client.Get(ctx, routeNN, original)
			require.NoErrorf(t, err, "error getting HTTPRoute: %v", err)

			// Sanity check
			kubernetes.HTTPRouteMustHaveLatestConditions(t, original)

			mutate := original.DeepCopy()
			mutate.Spec.Rules[0].BackendRefs[0].Name = "infra-backend-v2"
			err = suite.Client.Patch(ctx, mutate, client.MergeFrom(original))
			require.NoErrorf(t, err, "error patching the HTTPRoute: %v", err)

			kubernetes.HTTPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, metav1.Condition{
				Type:   string(v1.RouteConditionAccepted),
				Status: metav1.ConditionTrue,
				Reason: "", // any reason
			})
			kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

			updated := &v1.HTTPRoute{}
			err = suite.Client.Get(ctx, routeNN, updated)
			require.NoErrorf(t, err, "error getting Gateway: %v", err)

			// Sanity check
			kubernetes.HTTPRouteMustHaveLatestConditions(t, updated)

			require.NotEqual(t, original.Generation, updated.Generation, "generation should change after an update")
		})
	},
}
