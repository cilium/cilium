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
	ConformanceTests = append(ConformanceTests, GatewayModifyListeners)
}

var GatewayModifyListeners = suite.ConformanceTest{
	ShortName:   "GatewayModifyListeners",
	Description: "A Gateway in the gateway-conformance-infra namespace should handle adding and removing listeners.",
	Features: []features.FeatureName{
		features.SupportGateway,
	},
	Manifests: []string{"tests/gateway-modify-listeners.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		t.Run("should be able to add a listener that then becomes available for routing traffic", func(t *testing.T) {
			gwNN := types.NamespacedName{Name: "gateway-add-listener", Namespace: "gateway-conformance-infra"}
			namespaces := []string{"gateway-conformance-infra"}
			kubernetes.NamespacesMustBeReady(t, s.Client, s.TimeoutConfig, namespaces)

			// verify that the implementation is tracking the most recent resource changes
			kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)

			ctx, cancel := context.WithTimeout(context.Background(), s.TimeoutConfig.DefaultTestTimeout)
			defer cancel()
			original := &v1.Gateway{}
			err := s.Client.Get(ctx, gwNN, original)
			require.NoErrorf(t, err, "error getting Gateway: %v", err)

			all := v1.NamespacesFromAll

			mutate := original.DeepCopy()

			// add a new listener to the Gateway spec
			hostname := v1.Hostname("data.test.com")
			mutate.Spec.Listeners = append(mutate.Spec.Listeners, v1.Listener{
				Name:     "http",
				Port:     80,
				Protocol: v1.HTTPProtocolType,
				Hostname: &hostname,
				AllowedRoutes: &v1.AllowedRoutes{
					Namespaces: &v1.RouteNamespaces{From: &all},
				},
			})

			err = s.Client.Patch(ctx, mutate, client.MergeFrom(original))
			require.NoErrorf(t, err, "error patching the Gateway: %v", err)

			// Ensure the generation and observedGeneration sync up
			kubernetes.NamespacesMustBeReady(t, s.Client, s.TimeoutConfig, namespaces)

			listeners := []v1.ListenerStatus{
				{
					Name: v1.SectionName("https"),
					SupportedKinds: []v1.RouteGroupKind{{
						Group: (*v1.Group)(&v1.GroupVersion.Group),
						Kind:  v1.Kind("HTTPRoute"),
					}},
					Conditions: []metav1.Condition{
						{
							Type:   string(v1.ListenerConditionAccepted),
							Status: metav1.ConditionTrue,
							Reason: "", // any reason
						},
						{
							Type:   string(v1.ListenerConditionResolvedRefs),
							Status: metav1.ConditionTrue,
							Reason: "", // any reason
						},
					},
					AttachedRoutes: 1,
				},
				{
					Name: v1.SectionName("http"),
					SupportedKinds: []v1.RouteGroupKind{{
						Group: (*v1.Group)(&v1.GroupVersion.Group),
						Kind:  v1.Kind("HTTPRoute"),
					}},
					Conditions: []metav1.Condition{
						{
							Type:   string(v1.ListenerConditionAccepted),
							Status: metav1.ConditionTrue,
							Reason: "", // any reason
						},
						{
							Type:   string(v1.ListenerConditionResolvedRefs),
							Status: metav1.ConditionTrue,
							Reason: "", // any reason
						},
					},
					AttachedRoutes: 1,
				},
			}

			kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, gwNN, listeners)

			// verify that the implementation continues to keep up to date with the resource changes we've been making
			kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)

			updated := &v1.Gateway{}
			err = s.Client.Get(ctx, gwNN, updated)
			require.NoErrorf(t, err, "error getting Gateway: %v", err)

			require.NotEqual(t, original.Generation, updated.Generation, "generation should change after an update")
		})

		t.Run("should be able to remove listeners, which would then stop routing the relevant traffic", func(t *testing.T) {
			gwNN := types.NamespacedName{Name: "gateway-remove-listener", Namespace: "gateway-conformance-infra"}
			namespaces := []string{"gateway-conformance-infra"}
			kubernetes.NamespacesMustBeReady(t, s.Client, s.TimeoutConfig, namespaces)

			// verify that the implementation is tracking the most recent resource changes
			kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)

			ctx, cancel := context.WithTimeout(context.Background(), s.TimeoutConfig.DefaultTestTimeout)
			defer cancel()
			original := &v1.Gateway{}
			err := s.Client.Get(ctx, gwNN, original)
			require.NoErrorf(t, err, "error getting Gateway: %v", err)

			mutate := original.DeepCopy()
			require.Lenf(t, mutate.Spec.Listeners, 2, "the gateway must have 2 listeners")

			// remove the "https" Gateway listener, leaving only the "http" listener
			var newListeners []v1.Listener
			for _, listener := range mutate.Spec.Listeners {
				if listener.Name == "http" {
					newListeners = append(newListeners, listener)
				}
			}
			mutate.Spec.Listeners = newListeners

			err = s.Client.Patch(ctx, mutate, client.MergeFrom(original))
			require.NoErrorf(t, err, "error patching the Gateway: %v", err)

			// Ensure the generation and observedGeneration sync up
			kubernetes.NamespacesMustBeReady(t, s.Client, s.TimeoutConfig, namespaces)

			listeners := []v1.ListenerStatus{
				{
					Name: v1.SectionName("http"),
					SupportedKinds: []v1.RouteGroupKind{{
						Group: (*v1.Group)(&v1.GroupVersion.Group),
						Kind:  v1.Kind("HTTPRoute"),
					}},
					Conditions: []metav1.Condition{
						{
							Type:   string(v1.ListenerConditionAccepted),
							Status: metav1.ConditionTrue,
							Reason: "", // any reason
						},
						{
							Type:   string(v1.ListenerConditionResolvedRefs),
							Status: metav1.ConditionTrue,
							Reason: "", // any reason
						},
					},
					AttachedRoutes: 1,
				},
			}

			kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, gwNN, listeners)

			// verify that the implementation continues to keep up to date with the resource changes we've been making
			kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)

			updated := &v1.Gateway{}
			err = s.Client.Get(ctx, gwNN, updated)
			require.NoErrorf(t, err, "error getting Gateway: %v", err)

			require.NotEqual(t, original.Generation, updated.Generation, "generation should change after an update")
		})
	},
}
