/*
Copyright 2024 The Kubernetes Authors.

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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayInfrastructure)
}

var GatewayInfrastructure = suite.ConformanceTest{
	ShortName:   "GatewayInfrastructure",
	Description: "Propagation of metadata from Gateway infrastructure to generated components",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportGatewayInfrastructurePropagation,
	},
	Manifests: []string{
		"tests/gateway-infrastructure.yaml",
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		kubernetes.NamespacesMustBeReady(t, s.Client, s.TimeoutConfig, []string{ns})

		gwNN := types.NamespacedName{
			Name:      "gateway-with-infrastructure-metadata",
			Namespace: "gateway-conformance-infra",
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.TimeoutConfig.DefaultTestTimeout)
		defer cancel()

		t.Logf("waiting for namespace %s and Gateway %s to be ready for testing", gwNN.Namespace, gwNN.Name)
		kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)

		t.Logf("retrieving Gateway %s/%s", gwNN.Namespace, gwNN.Name)
		currentGW := &v1.Gateway{}
		err := s.Client.Get(ctx, gwNN, currentGW)
		require.NoError(t, err, "error getting Gateway: %v", err)
		t.Logf("verifying that the Gateway %s/%s is accepted with infrastructure declared", gwNN.Namespace, gwNN.Name)
		kubernetes.GatewayMustHaveCondition(t, s.Client, s.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(v1.GatewayConditionAccepted),
			Status: metav1.ConditionTrue,
		})

		t.Logf("verifying that generated resources for Gateway %s/%s have the proper gateway name label", gwNN.Namespace, gwNN.Name)
		// Don't check services because implementations may have special filtering logic (e.g. for LB annotations)
		// Instead, check service accounts for the gateway-name label first and then
		// fallback to Pod if that fails
		annotations := make(map[string]string, len(currentGW.Spec.Infrastructure.Annotations))
		labels := make(map[string]string, len(currentGW.Spec.Infrastructure.Labels))
		// Need to translate from (Annotation|Label)Key to string
		for k, v := range currentGW.Spec.Infrastructure.Annotations {
			annotations[string(k)] = string(v)
		}

		for k, v := range currentGW.Spec.Infrastructure.Labels {
			labels[string(k)] = string(v)
		}
		var foundResource bool
		saList := corev1.ServiceAccountList{}
		podList := corev1.PodList{}
		serviceList := corev1.ServiceList{}
		err = s.Client.List(ctx, &saList, client.MatchingLabels{"gateway.networking.k8s.io/gateway-name": gwNN.Name}, client.InNamespace(ns))
		require.NoError(t, err, "error listing ServiceAccounts")
		err = s.Client.List(ctx, &podList, client.MatchingLabels{"gateway.networking.k8s.io/gateway-name": gwNN.Name}, client.InNamespace(ns))
		require.NoError(t, err, "error listing Pods")
		err = s.Client.List(ctx, &serviceList, client.MatchingLabels{"gateway.networking.k8s.io/gateway-name": gwNN.Name}, client.InNamespace(ns))
		require.NoError(t, err, "error listing Services")
		if len(saList.Items) > 0 {
			foundResource = true
			sa := saList.Items[0]
			require.Subsetf(t, sa.Labels, labels, "expected Pod label set %v to contain all Gateway infrastructure labels %v", sa.Labels, labels)
			require.Subsetf(t, sa.Annotations, annotations, "expected Pod annotation set %v to contain all Gateway infrastructure annotations %v", sa.Annotations, annotations)
		}
		if len(podList.Items) > 0 {
			foundResource = true
			pod := podList.Items[0]
			require.Subsetf(t, pod.Labels, labels, "expected Pod label set %v to contain all Gateway infrastructure labels %v", pod.Labels, labels)
			require.Subsetf(t, pod.Annotations, annotations, "expected Pod annotation set %v to contain all Gateway infrastructure annotations %v", pod.Annotations, annotations)
		}
		if len(serviceList.Items) > 0 {
			foundResource = true
			service := serviceList.Items[0]
			require.Subsetf(t, service.Labels, labels, "expected Pod label set %v to contain all Gateway infrastructure labels %v", service.Labels, labels)
			require.Subsetf(t, service.Annotations, annotations, "expected Pod annotation set %v to contain all Gateway infrastructure annotations %v", service.Annotations, annotations)
		}

		require.True(t, foundResource, "expected to find a ServiceAccount, Pod, or Service with the gateway-name label")
	},
}
