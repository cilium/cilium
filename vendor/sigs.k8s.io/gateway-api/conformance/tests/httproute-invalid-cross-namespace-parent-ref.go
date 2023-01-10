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

	"sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteInvalidCrossNamespaceParentRef)
}

var HTTPRouteInvalidCrossNamespaceParentRef = suite.ConformanceTest{
	ShortName:   "HTTPRouteInvalidCrossNamespaceParentRef",
	Description: "A single HTTPRoute in the gateway-conformance-web-backend namespace should fail to attach to a Gateway in another namespace that it is not allowed to",
	Manifests:   []string{"tests/httproute-invalid-cross-namespace-parent-ref.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		routeName := types.NamespacedName{Name: "invalid-cross-namespace-parent-ref", Namespace: "gateway-conformance-web-backend"}
		gwName := types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}

		t.Run("Route should not have Parents set in status", func(t *testing.T) {
			kubernetes.HTTPRouteMustHaveNoAcceptedParents(t, suite.Client, routeName, 60)
		})

		t.Run("Gateway should have 0 Routes attached", func(t *testing.T) {
			require.Eventually(t, func() bool {
				gw := &v1alpha2.Gateway{}
				if err := suite.Client.Get(context.TODO(), gwName, gw); err != nil {
					t.Logf("error fetching gateway: %v", err)
					return false
				}

				// There are two valid ways to represent this:
				// 1. No listeners in status
				// 2. One listener in status with 0 attached routes
				if len(gw.Status.Listeners) == 0 {
					// No listeners in status.
					return true
				} else if len(gw.Status.Listeners) == 1 {
					// Listener with no attached routes
					return gw.Status.Listeners[0].AttachedRoutes == 0
				}
				return false
			}, time.Second*15, time.Second, "Expected no attached routes")
		})
	},
}
