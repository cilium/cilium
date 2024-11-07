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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayObservedGenerationBump)
}

var GatewayObservedGenerationBump = suite.ConformanceTest{
	ShortName:   "GatewayObservedGenerationBump",
	Description: "A Gateway in the gateway-conformance-infra namespace should update the observedGeneration in all of its Status.Conditions after an update to the spec",
	Features: []features.FeatureName{
		features.SupportGateway,
	},
	Manifests: []string{"tests/gateway-observed-generation-bump.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		gwNN := types.NamespacedName{Name: "gateway-observed-generation-bump", Namespace: "gateway-conformance-infra"}

		t.Run("observedGeneration should increment", func(t *testing.T) {
			namespaces := []string{"gateway-conformance-infra"}
			kubernetes.NamespacesMustBeReady(t, s.Client, s.TimeoutConfig, namespaces)

			// Sanity check
			kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)

			ctx, cancel := context.WithTimeout(context.Background(), s.TimeoutConfig.LatestObservedGenerationSet)
			defer cancel()
			original := &v1.Gateway{}
			err := s.Client.Get(ctx, gwNN, original)
			require.NoErrorf(t, err, "error getting Gateway: %v", err)

			all := v1.NamespacesFromAll

			mutate := original.DeepCopy()

			// mutate the Gateway Spec
			mutate.Spec.Listeners = append(mutate.Spec.Listeners, v1.Listener{
				Name:     "alternate",
				Hostname: ptr.To[v1.Hostname]("foo.com"),
				Port:     80,
				Protocol: v1.HTTPProtocolType,
				AllowedRoutes: &v1.AllowedRoutes{
					Namespaces: &v1.RouteNamespaces{From: &all},
				},
			})

			err = s.Client.Patch(ctx, mutate, client.MergeFrom(original))
			require.NoErrorf(t, err, "error patching the Gateway: %v", err)

			// Ensure the generation and observedGeneration sync up
			kubernetes.NamespacesMustBeReady(t, s.Client, s.TimeoutConfig, namespaces)

			// Sanity check
			kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)

			updated := &v1.Gateway{}
			err = s.Client.Get(ctx, gwNN, updated)
			require.NoErrorf(t, err, "error getting Gateway: %v", err)

			require.NotEqual(t, original.Generation, updated.Generation, "generation should change after an update")
		})
	},
}
