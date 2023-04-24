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
	ConformanceTests = append(ConformanceTests, GatewayClassObservedGenerationBump)
}

var GatewayClassObservedGenerationBump = suite.ConformanceTest{
	ShortName:   "GatewayClassObservedGenerationBump",
	Features:    []suite.SupportedFeature{suite.SupportGatewayClassObservedGenerationBump},
	Description: "A GatewayClass should update the observedGeneration in all of it's Status.Conditions after an update to the spec",
	Manifests:   []string{"tests/gatewayclass-observed-generation-bump.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		gwc := types.NamespacedName{Name: "gatewayclass-observed-generation-bump"}

		t.Run("observedGeneration should increment", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			kubernetes.GWCMustHaveAcceptedConditionAny(t, s.Client, s.TimeoutConfig, gwc.Name)

			original := &v1beta1.GatewayClass{}
			err := s.Client.Get(ctx, gwc, original)
			require.NoErrorf(t, err, "error getting GatewayClass: %v", err)

			// Sanity check
			kubernetes.GatewayClassMustHaveLatestConditions(t, original)

			mutate := original.DeepCopy()
			desc := "new"
			mutate.Spec.Description = &desc

			err = s.Client.Update(ctx, mutate)
			require.NoErrorf(t, err, "error updating the GatewayClass: %v", err)

			// Ensure the generation and observedGeneration sync up
			kubernetes.GWCMustHaveAcceptedConditionAny(t, s.Client, s.TimeoutConfig, gwc.Name)

			updated := &v1beta1.GatewayClass{}
			err = s.Client.Get(ctx, gwc, updated)
			require.NoErrorf(t, err, "error getting GatewayClass: %v", err)

			// Sanity check
			kubernetes.GatewayClassMustHaveLatestConditions(t, updated)

			require.NotEqual(t, original.Generation, updated.Generation, "generation should change after an update")
		})
	},
}
