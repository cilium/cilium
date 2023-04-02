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
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayObservedGenerationBump)
}

var GatewayObservedGenerationBump = suite.ConformanceTest{
	ShortName:   "GatewayObservedGenerationBump",
	Description: "A Gateway in the gateway-conformance-infra namespace should update the observedGeneration in all of it's Status.Conditions after an update to the spec",
	Manifests:   []string{"tests/gateway-observed-generation-bump.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {

		gwNN := types.NamespacedName{Name: "gateway-observed-generation-bump", Namespace: "gateway-conformance-infra"}

		t.Run("observedGeneration should increment", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			namespaces := []string{"gateway-conformance-infra"}
			kubernetes.NamespacesMustBeAccepted(t, s.Client, s.TimeoutConfig, namespaces)

			original := &v1beta1.Gateway{}
			err := s.Client.Get(ctx, gwNN, original)
			require.NoErrorf(t, err, "error getting Gateway: %v", err)

			// Sanity check
			kubernetes.GatewayMustHaveLatestConditions(t, original)

			all := v1beta1.NamespacesFromAll

			mutate := original.DeepCopy()

			// mutate the Gateway Spec
			mutate.Spec.Listeners = append(mutate.Spec.Listeners, v1beta1.Listener{
				Name:     "alternate",
				Port:     8080,
				Protocol: v1beta1.HTTPProtocolType,
				AllowedRoutes: &v1beta1.AllowedRoutes{
					Namespaces: &v1beta1.RouteNamespaces{From: &all},
				},
			})

			err = s.Client.Update(ctx, mutate)
			require.NoErrorf(t, err, "error updating the Gateway: %v", err)

			// Ensure the generation and observedGeneration sync up
			kubernetes.NamespacesMustBeAccepted(t, s.Client, s.TimeoutConfig, namespaces)

			updated := &v1beta1.Gateway{}
			err = s.Client.Get(ctx, gwNN, updated)
			require.NoErrorf(t, err, "error getting Gateway: %v", err)

			// Sanity check
			kubernetes.GatewayMustHaveLatestConditions(t, updated)

			require.NotEqual(t, original.Generation, updated.Generation, "generation should change after an update")
		})
	},
}
