// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestHTTPRouteValidateHeaderModifier(t *testing.T) {
	tests := []struct {
		name    string
		filters []gatewayv1.HTTPRouteFilter
		invalid bool
	}{
		{
			name: "valid request header modifier",
			filters: []gatewayv1.HTTPRouteFilter{{
				Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
				RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
					Set: []gatewayv1.HTTPHeader{{
						Name:  "X-Forwarded-Host",
						Value: "example.com",
					}},
				},
			}},
		},
		{
			name: "invalid host request header modifier",
			filters: []gatewayv1.HTTPRouteFilter{{
				Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
				RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
					Set: []gatewayv1.HTTPHeader{{
						Name:  "Host",
						Value: "example.com",
					}},
				},
			}},
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
						Rules: []gatewayv1.HTTPRouteRule{{Filters: tt.filters}},
					},
				},
			}

			cond, invalid := input.ValidateHeaderModifier()

			assert.Equal(t, tt.invalid, invalid)
			if invalid {
				assert.Equal(t, string(gatewayv1.RouteConditionAccepted), cond.Type)
				assert.Equal(t, metav1.ConditionFalse, cond.Status)
				assert.Equal(t, string(gatewayv1.RouteReasonUnsupportedValue), cond.Reason)
				assert.Equal(t, `Invalid header modifier: "Host" header is not supported`, cond.Message)
			}
		})
	}
}

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

func TestCheckBackendIsExistingServiceSetsResolvedRefsFalseForUnknownServicePort(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, gatewayv1.Install(scheme))

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "my-gw"}},
			},
			Rules: []gatewayv1.HTTPRouteRule{{
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: "backend-svc",
							Port: ptrTo(gatewayv1.PortNumber(8080)),
						},
					},
				}},
			}},
		},
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-svc",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{
				Name: "web",
				Port: 80,
			}},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(route, service).Build()
	input := &HTTPRouteInput{
		Ctx:            context.Background(),
		Logger:         slog.New(slog.DiscardHandler),
		Client:         cl,
		Grants:         nil,
		HTTPRoute:      route,
		ControllerName: "io.cilium/gateway-deployment-controller",
	}

	ok, err := CheckBackendIsExistingService(input, gatewayv1.ParentReference{Name: "my-gw"})
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, route.Status.Parents, 1)
	require.Len(t, route.Status.Parents[0].Conditions, 1)

	cond := route.Status.Parents[0].Conditions[0]
	assert.Equal(t, string(gatewayv1.RouteConditionResolvedRefs), cond.Type)
	assert.Equal(t, metav1.ConditionFalse, cond.Status)
	assert.Equal(t, string(gatewayv1.RouteReasonBackendNotFound), cond.Reason)
	assert.Equal(t, "Service port 8080 could not be resolved for backend default/backend-svc", cond.Message)
}

func ptrTo[T any](value T) *T {
	return &value
}
