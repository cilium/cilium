/*
Copyright 2025 The Kubernetes Authors.

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

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, BackendTLSPolicyObservedGenerationBump)
}

var BackendTLSPolicyObservedGenerationBump = suite.ConformanceTest{
	ShortName:   "BackendTLSPolicyObservedGenerationBump",
	Description: "A BackendTLSPolicy in the gateway-conformance-infra namespace should update the observedGeneration in all of its Status.Conditions after an update to the spec",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportBackendTLSPolicy,
	},
	Manifests: []string{"tests/backendtlspolicy-observed-generation-bump.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		policyNN := types.NamespacedName{Name: "observed-generation-bump", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}

		t.Run("observedGeneration should increment", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), suite.TimeoutConfig.LatestObservedGenerationSet)
			defer cancel()

			namespaces := []string{"gateway-conformance-infra"}
			kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, namespaces)

			original := &gatewayv1.BackendTLSPolicy{}
			err := suite.Client.Get(ctx, policyNN, original)
			require.NoError(t, err, "error getting HTTPRoute")

			// Sanity check
			kubernetes.BackendTLSPolicyMustHaveLatestConditions(t, original)

			mutate := original.DeepCopy()
			mutate.Spec.Validation.Hostname = "foo.example.com"
			err = suite.Client.Patch(ctx, mutate, client.MergeFrom(original))
			require.NoError(t, err, "error patching the BackendTLSPolicy")

			kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, metav1.Condition{
				Type:   string(gatewayv1.PolicyConditionAccepted),
				Status: metav1.ConditionTrue,
				Reason: "", // any reason
			})

			updated := &gatewayv1.BackendTLSPolicy{}
			err = suite.Client.Get(ctx, policyNN, updated)
			require.NoError(t, err, "error getting BackendTLSPolicy")

			// Sanity check
			kubernetes.BackendTLSPolicyMustHaveLatestConditions(t, updated)

			require.NotEqual(t, original.Generation, updated.Generation, "generation should change after an update")
		})
	},
}
