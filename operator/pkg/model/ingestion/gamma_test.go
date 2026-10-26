// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
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

func TestGammaRouteOrdering(t *testing.T) {
	inputs := map[string]GammaInput{
		"HTTPRoute": readGammaInput(t, "Mesh Split"),
		"GRPCRoute": readGammaInput(t, "Mesh GRPC Weight"),
	}
	for kind, input := range inputs {
		t.Run(kind, func(t *testing.T) {
			logger := hivetest.Logger(t)
			sorted := GammaInput{
				Services:        input.Services,
				ReferenceGrants: input.ReferenceGrants,
			}
			for i, meta := range []metav1.ObjectMeta{
				{Name: "route-z", CreationTimestamp: metav1.Unix(1, 0)},
				{Name: "route-a", CreationTimestamp: metav1.Unix(2, 0)},
				{Name: "route-b", CreationTimestamp: metav1.Unix(2, 0)},
			} {
				switch kind {
				case "HTTPRoute":
					route := input.HTTPRoutes[0].DeepCopy()
					route.Name = meta.Name
					route.CreationTimestamp = meta.CreationTimestamp
					route.Spec.ParentRefs[0].Port = ptr.To(gatewayv1.PortNumber(80))
					route.Spec.Rules = route.Spec.Rules[:1]
					route.Spec.Rules[0].Matches[0].Path.Value = ptr.To(fmt.Sprintf("/method-%d", i))
					sorted.HTTPRoutes = append(sorted.HTTPRoutes, *route)
				case "GRPCRoute":
					route := input.GRPCRoutes[0].DeepCopy()
					route.Name = meta.Name
					route.CreationTimestamp = meta.CreationTimestamp
					route.Spec.Rules[0].BackendRefs = route.Spec.Rules[0].BackendRefs[:2]
					route.Spec.Rules[0].Matches = []gatewayv1.GRPCRouteMatch{{
						Method: &gatewayv1.GRPCMethodMatch{
							Type:    ptr.To(gatewayv1.GRPCMethodMatchExact),
							Service: ptr.To("example.Echo"),
							Method:  ptr.To(fmt.Sprintf("Method%d", i)),
						},
					}}
					sorted.GRPCRoutes = append(sorted.GRPCRoutes, *route)
				}
			}

			expected := GammaHTTPRoutes(logger, sorted)
			require.Len(t, expected, 3)
			for _, order := range [][3]int{
				{0, 1, 2},
				{0, 2, 1},
				{1, 0, 2},
				{1, 2, 0},
				{2, 0, 1},
				{2, 1, 0},
			} {
				t.Run(fmt.Sprint(order), func(t *testing.T) {
					permuted := GammaInput{
						Services:        sorted.Services,
						ReferenceGrants: sorted.ReferenceGrants,
					}
					for _, i := range order {
						switch kind {
						case "HTTPRoute":
							permuted.HTTPRoutes = append(permuted.HTTPRoutes, sorted.HTTPRoutes[i])
						case "GRPCRoute":
							permuted.GRPCRoutes = append(permuted.GRPCRoutes, sorted.GRPCRoutes[i])
						}
					}
					originalHTTPRoutes := slices.Clone(permuted.HTTPRoutes)
					originalGRPCRoutes := slices.Clone(permuted.GRPCRoutes)
					actual := GammaHTTPRoutes(logger, permuted)

					require.Equal(t, originalHTTPRoutes, permuted.HTTPRoutes, "HTTPRoute input was mutated")
					require.Equal(t, originalGRPCRoutes, permuted.GRPCRoutes, "GRPCRoute input was mutated")
					require.Equal(t, expected, actual, "Listeners changed with route input order")
				})
			}
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
