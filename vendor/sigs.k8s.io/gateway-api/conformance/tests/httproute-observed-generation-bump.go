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
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteObservedGenerationBump)
}

var HTTPRouteObservedGenerationBump = suite.ConformanceTest{
	ShortName:   "HTTPRouteObservedGenerationBump",
	Description: "A HTTPRoute in the gateway-conformance-infra namespace should update the observedGeneration in all of it's Status.Conditions after an update to the spec",
	Manifests:   []string{"tests/httproute-observed-generation-bump.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {

		routeNN := types.NamespacedName{Name: "observed-generation-bump", Namespace: "gateway-conformance-infra"}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}

		acceptedCondition := metav1.Condition{
			Type:   string(v1beta1.RouteConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: "", // any reason
		}

		t.Run("observedGeneration should increment", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			namespaces := []string{"gateway-conformance-infra"}
			kubernetes.NamespacesMustBeAccepted(t, s.Client, s.TimeoutConfig, namespaces)

			original := &v1beta1.HTTPRoute{}
			err := s.Client.Get(ctx, routeNN, original)
			require.NoErrorf(t, err, "error getting HTTPRoute: %v", err)

			// Sanity check
			kubernetes.HTTPRouteMustHaveLatestConditions(t, original)

			mutate := original.DeepCopy()
			mutate.Spec.Rules[0].BackendRefs[0].Name = "infra-backend-v2"
			err = s.Client.Update(ctx, mutate)
			require.NoErrorf(t, err, "error updating the HTTPRoute: %v", err)

			kubernetes.HTTPRouteMustHaveCondition(t, s.Client, s.TimeoutConfig, routeNN, gwNN, acceptedCondition)

			updated := &v1beta1.HTTPRoute{}
			err = s.Client.Get(ctx, routeNN, updated)
			require.NoErrorf(t, err, "error getting Gateway: %v", err)

			// Sanity check
			kubernetes.HTTPRouteMustHaveLatestConditions(t, updated)

			require.NotEqual(t, original.Generation, updated.Generation, "generation should change after an update")
		})
	},
}
