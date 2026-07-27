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
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, UDPRouteMultipleRoutesAttachment)
}

var UDPRouteMultipleRoutesAttachment = confsuite.ConformanceTest{
	ShortName: "UDPRouteMultipleRoutesAttachment",
	Description: "When two UDPRoutes target the same Gateway listener, both must report Accepted=True. " +
		"Only the oldest route is attached and receives traffic; the listener's AttachedRoutes count must reflect both.",
	Manifests: []string{"tests/udproute-multiple-routes-attachment.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportUDPRoute,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		gwNN := types.NamespacedName{Name: "udp-multi-route-attach-gateway", Namespace: ns}
		olderRouteNN := types.NamespacedName{Name: "udproute-attach-older", Namespace: ns}
		newerRouteNN := types.NamespacedName{Name: "udproute-attach-newer", Namespace: ns}

		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		// Wait for the Gateway and the older UDPRoute to be ready before introducing the
		// second route, so creation-time ordering is unambiguous.
		gwAddr := kubernetes.GatewayAndUDPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName,
			kubernetes.NewGatewayRef(gwNN, "udp"), olderRouteNN)

		// CreationTimestamp has second-level precision; sleep ensures the second route
		// is strictly newer than the first.
		time.Sleep(time.Second)

		newerRoute := &gatewayv1.UDPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      newerRouteNN.Name,
				Namespace: newerRouteNN.Namespace,
			},
			Spec: gatewayv1.UDPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{{
						Name:        gatewayv1.ObjectName(gwNN.Name),
						SectionName: ptr.To(gatewayv1.SectionName("udp")),
					}},
				},
				Rules: []gatewayv1.UDPRouteRule{{
					BackendRefs: []gatewayv1.BackendRef{{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: gatewayv1.ObjectName("udp-attach-backend-2"),
							Port: ptr.To(gatewayv1.PortNumber(8080)),
						},
					}},
				}},
			},
		}
		suite.Applier.MustApplyObjectsWithCleanup(t, suite.Client, suite.TimeoutConfig, []client.Object{newerRoute}, suite.CleanupTestResources)

		acceptedCond := metav1.Condition{
			Type:   string(gatewayv1.RouteConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: string(gatewayv1.RouteReasonAccepted),
		}

		t.Run("Both UDPRoutes should be Accepted by the Gateway", func(t *testing.T) {
			// Both routes report Accepted=True; the newer route is rejected at the
			// listener-attachment level rather than via the route's Accepted condition.
			kubernetes.UDPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, olderRouteNN, gwNN, acceptedCond)
			kubernetes.UDPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, newerRouteNN, gwNN, acceptedCond)
		})

		t.Run("Gateway listener should report 2 attached Routes", func(t *testing.T) {
			listeners := []gatewayv1.ListenerStatus{{
				Name: gatewayv1.SectionName("udp"),
				SupportedKinds: []gatewayv1.RouteGroupKind{{
					Group: ptr.To(gatewayv1.Group(gatewayv1.GroupName)),
					Kind:  gatewayv1.Kind("UDPRoute"),
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

		t.Run("Only the oldest UDPRoute should receive traffic", func(t *testing.T) {
			// https://gateway-api.sigs.k8s.io/guides/api-design/#conflicts, only the oldest route is bound to the
			// listener; UDP datagrams must be answered by udp-attach-backend-1 pods
			// and never by udp-attach-backend-2 pods.
			const (
				probeTimeout = 2 * time.Second
				probes       = 20
			)
			pollErr := wait.PollUntilContextTimeout(t.Context(), time.Second, suite.TimeoutConfig.DefaultTestTimeout, true,
				func(ctx context.Context) (bool, error) {
					for i := range probes {
						pod, err := udpEchoSendOnce(ctx, gwAddr, probeTimeout)
						if err != nil {
							tlog.Logf(t, "UDP probe %d failed, will retry: %v", i+1, err)
							return false, nil
						}
						backend := extractBackendName(pod)
						if backend != "udp-attach-backend-1" {
							return false, fmt.Errorf("UDP traffic reached unexpected backend %q (pod %q); only udp-attach-backend-1 should receive traffic", backend, pod)
						}
					}
					return true, nil
				})
			if pollErr != nil {
				t.Fatalf("UDP traffic verification failed: %v", pollErr)
			}
		})
	},
}
