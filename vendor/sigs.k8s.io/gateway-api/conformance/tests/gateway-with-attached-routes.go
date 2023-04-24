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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayWithAttachedRoutes)
}

var GatewayWithAttachedRoutes = suite.ConformanceTest{
	ShortName:   "GatewayWithAttachedRoutes",
	Description: "A Gateway in the gateway-conformance-infra namespace should be attached to routes.",
	Manifests:   []string{"tests/gateway-with-attached-routes.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		t.Run("Gateway listener should have one valid http routes attached", func(t *testing.T) {
			gwNN := types.NamespacedName{Name: "gateway-with-one-attached-route", Namespace: "gateway-conformance-infra"}
			listeners := []v1beta1.ListenerStatus{{
				Name: v1beta1.SectionName("http"),
				SupportedKinds: []v1beta1.RouteGroupKind{{
					Group: (*v1beta1.Group)(&v1beta1.GroupVersion.Group),
					Kind:  v1beta1.Kind("HTTPRoute"),
				}},
				Conditions: []metav1.Condition{{
					Type:   string(v1beta1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: "", //any reason
				}},
				AttachedRoutes: 1,
			}}

			kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, gwNN, listeners)
		})

		t.Run("Gateway listener should have two valid http routes attached", func(t *testing.T) {
			gwNN := types.NamespacedName{Name: "gateway-with-two-attached-routes", Namespace: "gateway-conformance-infra"}
			listeners := []v1beta1.ListenerStatus{{
				Name: v1beta1.SectionName("http"),
				SupportedKinds: []v1beta1.RouteGroupKind{{
					Group: (*v1beta1.Group)(&v1beta1.GroupVersion.Group),
					Kind:  v1beta1.Kind("HTTPRoute"),
				}},
				Conditions: []metav1.Condition{{
					Type:   string(v1beta1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: "", //any reason
				}},
				AttachedRoutes: 2,
			}}

			kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, gwNN, listeners)
		})
	},
}
