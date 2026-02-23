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
	"k8s.io/apimachinery/pkg/types"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayOptionalAddressValue)
}

var GatewayOptionalAddressValue = suite.ConformanceTest{
	ShortName:   "GatewayOptionalAddressValue",
	Description: "Check Gateway Support for GatewayAddressEmpty feature",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportGatewayAddressEmpty,
	},
	Provisional: true,
	Manifests: []string{
		"tests/gateway-optional-address-value.yaml",
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		kubernetes.NamespacesMustBeReady(t, s.Client, s.TimeoutConfig, []string{ns})

		gwNN := types.NamespacedName{
			Name:      "gateway-without-address-value",
			Namespace: "gateway-conformance-infra",
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.TimeoutConfig.DefaultTestTimeout)
		defer cancel()

		t.Logf("waiting for Gateway %s to be ready for testing", gwNN.Name)
		kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)

		t.Logf("retrieving Gateway %s/%s", gwNN.Namespace, gwNN.Name)
		currentGW := &v1.Gateway{}
		err := s.Client.Get(ctx, gwNN, currentGW)
		require.NoError(t, err, "error getting Gateway: %v", err)
		t.Logf("verifying that the Gateway %s/%s is accepted", gwNN.Namespace, gwNN.Name)
		_, err = kubernetes.WaitForGatewayAddress(t, s.Client, s.TimeoutConfig, kubernetes.NewGatewayRef(gwNN, "http"))
		require.NoError(t, err, "timed out waiting for Gateway address to be assigned")
	},
}
