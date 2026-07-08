// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestGRPCRouteValidateMatchRegexps(t *testing.T) {
	tests := []struct {
		name    string
		match   gatewayv1.GRPCRouteMatch
		invalid bool
	}{
		{
			name: "valid method regex",
			match: gatewayv1.GRPCRouteMatch{Method: &gatewayv1.GRPCMethodMatch{
				Type:    new(gatewayv1.GRPCMethodMatchRegularExpression),
				Service: new("^presence$"),
				Method:  new("^(Hello|Goodbye)$"),
			}},
		},
		{
			name: "invalid method.service regex",
			match: gatewayv1.GRPCRouteMatch{Method: &gatewayv1.GRPCMethodMatch{
				Type:    new(gatewayv1.GRPCMethodMatchRegularExpression),
				Service: new("^ordersV[12$"),
			}},
			invalid: true,
		},
		{
			name: "invalid method.method regex",
			match: gatewayv1.GRPCRouteMatch{Method: &gatewayv1.GRPCMethodMatch{
				Type:   new(gatewayv1.GRPCMethodMatchRegularExpression),
				Method: new(".(unclosed"),
			}},
			invalid: true,
		},
		{
			name: "valid header regex",
			match: gatewayv1.GRPCRouteMatch{Headers: []gatewayv1.GRPCHeaderMatch{{
				Type:  new(gatewayv1.GRPCHeaderMatchRegularExpression),
				Name:  "X-Device-Id",
				Value: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
			}}},
		},
		{
			name: "invalid header regex",
			match: gatewayv1.GRPCRouteMatch{Headers: []gatewayv1.GRPCHeaderMatch{{
				Type:  new(gatewayv1.GRPCHeaderMatchRegularExpression),
				Name:  "X-Device-Id",
				Value: "****invalid",
			}}},
			invalid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &GRPCRouteInput{
				ControllerName: "io.cilium/gateway-controller",
				GRPCRoute: &gatewayv1.GRPCRoute{
					Spec: gatewayv1.GRPCRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{{Name: "my-gw"}},
						},
						Rules: []gatewayv1.GRPCRouteRule{{Matches: []gatewayv1.GRPCRouteMatch{tt.match}}},
					},
				},
			}

			cond, invalid := input.ValidateMatchRegexps()

			assert.Equal(t, tt.invalid, invalid)
			if invalid {
				assert.Equal(t, string(gatewayv1.RouteConditionAccepted), cond.Type)
				assert.Equal(t, metav1.ConditionFalse, cond.Status)
				assert.Equal(t, string(gatewayv1.RouteReasonUnsupportedValue), cond.Reason)
			}
		})
	}
}
