// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestHTTPRouteValidateMatchRegexps(t *testing.T) {
	tests := []struct {
		name    string
		match   gatewayv1.HTTPRouteMatch
		invalid bool
	}{
		{
			name: "valid path regex",
			match: gatewayv1.HTTPRouteMatch{Path: &gatewayv1.HTTPPathMatch{
				Type:  new(gatewayv1.PathMatchRegularExpression),
				Value: new("/api/v[0-9]/.+"),
			}},
		},
		{
			name: "invalid path regex",
			match: gatewayv1.HTTPRouteMatch{Path: &gatewayv1.HTTPPathMatch{
				Type:  new(gatewayv1.PathMatchRegularExpression),
				Value: new("[unterminated"),
			}},
			invalid: true,
		},
		{
			name: "valid header regex",
			match: gatewayv1.HTTPRouteMatch{Headers: []gatewayv1.HTTPHeaderMatch{{
				Type:  new(gatewayv1.HeaderMatchRegularExpression),
				Name:  "X-Consumer-Key",
				Value: "^[A-Za-z0-9]{16,32}$",
			}}},
		},
		{
			name: "invalid header regex",
			match: gatewayv1.HTTPRouteMatch{Headers: []gatewayv1.HTTPHeaderMatch{{
				Type:  new(gatewayv1.HeaderMatchRegularExpression),
				Name:  "X-Consumer-Key",
				Value: "(unclosed",
			}}},
			invalid: true,
		},
		{
			name: "valid queryParam regex",
			match: gatewayv1.HTTPRouteMatch{QueryParams: []gatewayv1.HTTPQueryParamMatch{{
				Type:  new(gatewayv1.QueryParamMatchRegularExpression),
				Name:  "ref",
				Value: "^[a-z_]{8,16}[0-9]{1,5}$",
			}}},
		},
		{
			name: "invalid queryParam regex",
			match: gatewayv1.HTTPRouteMatch{QueryParams: []gatewayv1.HTTPQueryParamMatch{{
				Type:  new(gatewayv1.QueryParamMatchRegularExpression),
				Name:  "ref",
				Value: "(?invalidflag)",
			}}},
			invalid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &HTTPRouteInput{
				ControllerName: "io.cilium/gateway-controller",
				HTTPRoute: &gatewayv1.HTTPRoute{
					Spec: gatewayv1.HTTPRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{{Name: "my-gw"}},
						},
						Rules: []gatewayv1.HTTPRouteRule{{Matches: []gatewayv1.HTTPRouteMatch{tt.match}}},
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

func TestHTTPRouteRuleGetBackendRefsIncludesFilterBackends(t *testing.T) {
	rule := &HTTPRouteRule{
		Rule: gatewayv1.HTTPRouteRule{
			BackendRefs: []gatewayv1.HTTPBackendRef{
				{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: "backend-svc",
						},
					},
				},
			},
			Filters: []gatewayv1.HTTPRouteFilter{
				{
					Type: gatewayv1.HTTPRouteFilterRequestMirror,
					RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
						BackendRef: gatewayv1.BackendObjectReference{
							Name: "mirror-svc",
						},
					},
				},
				{
					Type: gatewayv1.HTTPRouteFilterExternalAuth,
					ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
						BackendRef: gatewayv1.BackendObjectReference{
							Name: "auth-svc",
						},
					},
				},
			},
		},
	}

	refs := rule.GetBackendRefs()
	require.Len(t, refs, 3)
	assert.Equal(t, gatewayv1.ObjectName("backend-svc"), refs[0].Name)
	assert.Equal(t, gatewayv1.ObjectName("mirror-svc"), refs[1].Name)
	assert.Equal(t, gatewayv1.ObjectName("auth-svc"), refs[2].Name)
}
