// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	basedGammaTestdataDir = "testdata/gamma"
)

func TestGammaConformance(t *testing.T) {
	tests := map[string]struct{}{
		"Mesh Split":          {},
		"Mesh Ports":          {},
		"Mesh Frontend":       {},
		"multiple_parentRefs": {},
		"multiple_HTTPRoutes": {},
		"Mesh GRPC Weight":    {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			input := readGammaInput(t, name)
			listeners := GammaHTTPRoutes(logger, input)

			expected := []model.HTTPListener{}
			readOutput(t, fmt.Sprintf("%s/%s/%s", basedGammaTestdataDir, rewriteTestName(name), "output-listeners.yaml"), &expected)

			require.Equal(t, expected, listeners, "Listeners did not match")
		})
	}
}

func readGammaInput(t *testing.T, testName string) GammaInput {
	input := GammaInput{}

	readInput(t, fmt.Sprintf("%s/%s/%s", basedGammaTestdataDir, rewriteTestName(testName), "input-httproute.yaml"), &input.HTTPRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGammaTestdataDir, rewriteTestName(testName), "input-grpcroute.yaml"), &input.GRPCRoutes)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGammaTestdataDir, rewriteTestName(testName), "input-service.yaml"), &input.Services)
	readInput(t, fmt.Sprintf("%s/%s/%s", basedGammaTestdataDir, rewriteTestName(testName), "input-referencegrant.yaml"), &input.ReferenceGrants)

	return input
}

// TestGammaSourceServiceScoping proves that a Route parented by more than one
// Service only contributes Listeners for the Service currently being
// reconciled. Without scoping, reconciling one Service would also program the
// other Service's Listeners into that reconciliation's CEC.
func TestGammaSourceServiceScoping(t *testing.T) {
	const namespace = "gamma-scoping"

	gammaService := func(name string) corev1.Service {
		return corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{
						Name:        "http",
						Port:        80,
						Protocol:    corev1.ProtocolTCP,
						AppProtocol: ptr.To("http"),
					},
					{
						Name:        "grpc",
						Port:        8080,
						Protocol:    corev1.ProtocolTCP,
						AppProtocol: ptr.To("grpc"),
					},
				},
			},
		}
	}

	serviceParent := func(name string) gatewayv1.ParentReference {
		return gatewayv1.ParentReference{
			Group: ptr.To(gatewayv1.Group(corev1.GroupName)),
			Kind:  ptr.To(gatewayv1.Kind("Service")),
			Name:  gatewayv1.ObjectName(name),
		}
	}

	echoA := gammaService("echo-a")
	echoB := gammaService("echo-b")

	parentRefs := []gatewayv1.ParentReference{serviceParent("echo-a"), serviceParent("echo-b")}

	input := GammaInput{
		Services: []corev1.Service{echoA, echoB},
		HTTPRoutes: []gatewayv1.HTTPRoute{{
			ObjectMeta: metav1.ObjectMeta{Name: "http-route", Namespace: namespace},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parentRefs},
				Rules: []gatewayv1.HTTPRouteRule{{
					BackendRefs: []gatewayv1.HTTPBackendRef{{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend",
								Port: ptr.To(gatewayv1.PortNumber(8080)),
							},
						},
					}},
				}},
			},
		}},
		GRPCRoutes: []gatewayv1.GRPCRoute{{
			ObjectMeta: metav1.ObjectMeta{Name: "grpc-route", Namespace: namespace},
			Spec: gatewayv1.GRPCRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: parentRefs},
				Rules: []gatewayv1.GRPCRouteRule{{
					BackendRefs: []gatewayv1.GRPCBackendRef{{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend",
								Port: ptr.To(gatewayv1.PortNumber(8080)),
							},
						},
					}},
				}},
			},
		}},
	}

	tests := map[string]struct {
		sourceService *corev1.Service
		expected      []string
	}{
		"unscoped input keeps every Service parent": {
			sourceService: nil,
			expected: []string{
				"gamma-scoping-echo-a-80",
				"gamma-scoping-echo-b-80",
				"gamma-scoping-echo-a-8080",
				"gamma-scoping-echo-b-8080",
			},
		},
		"scoping to echo-a drops the echo-b parent": {
			sourceService: &echoA,
			expected:      []string{"gamma-scoping-echo-a-80", "gamma-scoping-echo-a-8080"},
		},
		"scoping to echo-b drops the echo-a parent": {
			sourceService: &echoB,
			expected:      []string{"gamma-scoping-echo-b-80", "gamma-scoping-echo-b-8080"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			scoped := input
			scoped.SourceService = tc.sourceService

			listeners := GammaHTTPRoutes(hivetest.Logger(t), scoped)

			names := make([]string, 0, len(listeners))
			for _, l := range listeners {
				names = append(names, l.Name)
			}
			require.Equal(t, tc.expected, names)
		})
	}
}
