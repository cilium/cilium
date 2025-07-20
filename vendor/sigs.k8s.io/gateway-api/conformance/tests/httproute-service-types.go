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
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	client "sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteServiceTypes)
}

var HTTPRouteServiceTypes = suite.ConformanceTest{
	ShortName:   "HTTPRouteServiceTypes",
	Description: "A single HTTPRoute should be able to route traffic to various service type backends",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/httproute-service-types.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		var (
			typeManualEndpointSlices = []string{
				"manual-endpointslices",
				"headless-manual-endpointslices",
			}

			typeManaged = []string{
				"headless",
			}

			serviceTypes = make([]string, 0, len(typeManualEndpointSlices)+len(typeManaged))

			ctx     = context.TODO()
			ns      = "gateway-conformance-infra"
			routeNN = types.NamespacedName{Name: "service-types", Namespace: ns}
			gwNN    = types.NamespacedName{Name: "same-namespace", Namespace: ns}
		)

		serviceTypes = append(serviceTypes, typeManualEndpointSlices...)
		serviceTypes = append(serviceTypes, typeManaged...)

		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		deployment := &appsv1.Deployment{}
		err := suite.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: "infra-backend-v1"}, deployment)
		require.NoError(t, err, "Failed to fetch Deployment 'infra-backend-v1'")

		selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
		require.NoError(t, err, "Failed to parse Deployment selector")

		// Setup Manual Endpoints
		pods := &corev1.PodList{}
		err = suite.Client.List(ctx, pods, client.MatchingLabelsSelector{Selector: selector}, client.InNamespace(ns))
		require.NoError(t, err, "Failed to list 'infra-backend-v1' Pods")
		require.NotEmpty(t, pods, "Expected 'infra-backend-v1' to have running Pods")

		setupEndpointSlices(t, suite.Client, typeManualEndpointSlices, ns, pods)

		for i, path := range serviceTypes {
			expected := http.ExpectedResponse{
				Request:   http.Request{Path: "/" + path},
				Response:  http.Response{StatusCode: 200},
				Backend:   "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
			}

			t.Run(expected.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, expected)
			})
		}
	},
}

func setupEndpointSlices(t *testing.T, klient client.Client, endpointPrefixes []string, ns string, pods *corev1.PodList) {
	ipFamilies := []struct {
		endpointSuffix string
		isMember       func(ip netip.Addr) bool
	}{{
		endpointSuffix: "ip4",
		isMember:       netip.Addr.Is4,
	}, {
		endpointSuffix: "ip6",
		isMember:       netip.Addr.Is6,
	}}

	for _, ipFamily := range ipFamilies {
		for _, endpointPrefix := range endpointPrefixes {
			endpointName := fmt.Sprintf("%s-%s", endpointPrefix, ipFamily.endpointSuffix)
			endpointSlice := &discoveryv1.EndpointSlice{}

			err := klient.Get(context.TODO(), client.ObjectKey{Name: endpointName, Namespace: ns}, endpointSlice)
			require.NoErrorf(t, err, "Unable to fetch EndpointSlice %q", endpointName)

			patch := client.MergeFrom(endpointSlice.DeepCopy())
			endpointSlice.Endpoints = make([]discoveryv1.Endpoint, 0, len(pods.Items))

			for _, pod := range pods.Items {
				for _, podIP := range pod.Status.PodIPs {
					ip, err := netip.ParseAddr(podIP.IP) //nolint:govet
					require.NoErrorf(t, err, "Pod IP %q was not valid", podIP.IP)

					if !ipFamily.isMember(ip) {
						continue
					}

					endpoint := discoveryv1.Endpoint{
						Addresses: []string{podIP.IP},
						Conditions: discoveryv1.EndpointConditions{
							Ready:       ptr.To(true),
							Serving:     ptr.To(true),
							Terminating: ptr.To(false),
						},
						NodeName: ptr.To(pod.Spec.NodeName),
						TargetRef: &corev1.ObjectReference{
							Kind:      "Pod",
							Name:      pod.GetName(),
							Namespace: pod.GetNamespace(),
							UID:       pod.GetUID(),
						},
					}
					endpointSlice.Endpoints = append(endpointSlice.Endpoints, endpoint)
				}
			}

			if len(endpointSlice.Endpoints) == 0 {
				continue
			}

			err = klient.Patch(context.TODO(), endpointSlice, patch)
			require.NoErrorf(t, err, "Failed to patch EndpointSlice %q", endpointName)
		}
	}
}
