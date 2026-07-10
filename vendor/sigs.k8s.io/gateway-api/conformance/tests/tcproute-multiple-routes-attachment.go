/*
Copyright The Kubernetes Authors.

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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tcp"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, TCPRouteMultipleRoutesAttachment)
}

var TCPRouteMultipleRoutesAttachment = confsuite.ConformanceTest{
	ShortName: "TCPRouteMultipleRoutesAttachment",
	Description: "When two TCPRoutes target the same Gateway listener, both must report Accepted=True. " +
		"Only the oldest route is attached to the listener, and the listener's AttachedRoutes count must reflect this.",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTCPRoute,
	},
	Manifests: []string{"tests/tcproute-multiple-routes-attachment.yaml"},
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		gwNN := types.NamespacedName{Name: "tcp-multi-route-attach-gateway", Namespace: ns}
		olderRouteNN := types.NamespacedName{Name: "tcproute-attach-older", Namespace: ns}
		newerRouteNN := types.NamespacedName{Name: "tcproute-attach-newer", Namespace: ns}

		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		// Wait for the Gateway and the older TCPRoute to be ready before introducing the
		// second route, so creation-time ordering is unambiguous.
		gwAddr := kubernetes.GatewayAndTCPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN, "tcp"), olderRouteNN)

		// CreationTimestamp has second-level precision; sleep ensures the second route
		// is strictly newer than the first.
		time.Sleep(time.Second)

		newerRoute := &gatewayv1.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      newerRouteNN.Name,
				Namespace: newerRouteNN.Namespace,
			},
			Spec: gatewayv1.TCPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{{
						Name:        gatewayv1.ObjectName(gwNN.Name),
						SectionName: ptr.To(gatewayv1.SectionName("tcp")),
					}},
				},
				Rules: []gatewayv1.TCPRouteRule{{
					BackendRefs: []gatewayv1.BackendRef{{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: gatewayv1.ObjectName("tcp-attach-backend-2"),
							Port: ptr.To(gatewayv1.PortNumber(3000)),
						},
					}},
				}},
			},
		}
		suite.Applier.MustApplyObjectsWithCleanup(t, suite.Client, suite.TimeoutConfig, []client.Object{newerRoute}, suite.Cleanup)

		acceptedCond := metav1.Condition{
			Type:   string(gatewayv1.RouteConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: string(gatewayv1.RouteReasonAccepted),
		}

		t.Run("Both TCPRoutes should be Accepted by the Gateway", func(t *testing.T) {
			// Both routes report Accepted=True; the newer route is rejected at the
			// listener-attachment level rather than via the route's Accepted condition.
			kubernetes.TCPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, olderRouteNN, gwNN, acceptedCond)
			kubernetes.TCPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, newerRouteNN, gwNN, acceptedCond)
		})

		t.Run("Gateway listener should report 2 attached Routes", func(t *testing.T) {
			listeners := []gatewayv1.ListenerStatus{{
				Name: gatewayv1.SectionName("tcp"),
				SupportedKinds: []gatewayv1.RouteGroupKind{{
					Group: ptr.To(gatewayv1.Group(gatewayv1.GroupName)),
					Kind:  gatewayv1.Kind("TCPRoute"),
				}},
				Conditions: []metav1.Condition{{
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.ListenerReasonAccepted),
				}},
				AttachedRoutes: 2,
			}}
			kubernetes.GatewayStatusMustHaveListeners(t, suite.Client, suite.TimeoutConfig, gwNN, listeners)
		})

		t.Run("Only the oldest TCPRoute should receive traffic", func(t *testing.T) {
			// https://gateway-api.sigs.k8s.io/guides/api-design/#conflicts, only the oldest route is bound to the
			// listener; traffic must reach pods backing tcp-attach-backend-1 and never
			// pods backing tcp-attach-backend-2.
			//
			// First wait for the data plane to converge so the older route is
			// consistently serving traffic.
			tcp.MakeTCPRequestAndExpectEventuallyValidResponse(t, suite.TimeoutConfig, gwAddr, nil, "", false,
				tcp.ExpectedResponse{
					Backend:   "tcp-attach-backend-1",
					Namespace: ns,
				})

			// Sample many connections and assert the newer route's backend is
			// never selected. A single request can hit the older backend by
			// chance even if both routes were attached, so repeated sampling
			// strengthens the guarantee that only the oldest route is bound.
			const (
				sampleCount   = 100
				perReqTimeout = 5 * time.Second
			)
			const olderBackendPrefix = "tcp-attach-backend-1-"
			const newerBackendPrefix = "tcp-attach-backend-2-"

			for i := range sampleCount {
				pod, err := tcp.EchoSendOnce(t.Context(), gwAddr, perReqTimeout)
				require.NoErrorf(t, err, "TCP echo request %d/%d failed", i+1, sampleCount)
				require.Falsef(t, strings.HasPrefix(pod, newerBackendPrefix),
					"request %d/%d reached newer route backend %q; only the oldest route should be attached", i+1, sampleCount, pod)
				require.Truef(t, strings.HasPrefix(pod, olderBackendPrefix),
					"request %d/%d reached unexpected backend %q; expected pod from %q", i+1, sampleCount, pod, olderBackendPrefix)
			}
		})
	},
}
