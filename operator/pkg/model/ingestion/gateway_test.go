// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/model"
)

type gwTestCase struct {
	input Input
	want  []model.HTTPListener
}

var basicHTTP = Input{
	GatewayClass: gatewayv1beta1.GatewayClass{},
	Gateway: gatewayv1beta1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: "gateway.networking.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			Listeners: []gatewayv1beta1.Listener{
				{
					Name:     "prod-web-gw",
					Port:     80,
					Protocol: "HTTP",
				},
			},
		},
	},
	HTTPRoutes: []gatewayv1beta1.HTTPRoute{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-app-1",
				Namespace: "default",
			},
			Spec: gatewayv1beta1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1beta1.CommonRouteSpec{
					ParentRefs: []gatewayv1beta1.ParentReference{
						{
							Name: "my-gateway",
						},
					},
				},
				Rules: []gatewayv1beta1.HTTPRouteRule{
					{
						Matches: []gatewayv1beta1.HTTPRouteMatch{
							{
								Path: &gatewayv1beta1.HTTPPathMatch{
									Type:  pathMatchTypePtr("PathPrefix"),
									Value: strp("/bar"),
								},
							},
						},
						BackendRefs: []gatewayv1beta1.HTTPBackendRef{
							{
								BackendRef: gatewayv1beta1.BackendRef{
									BackendObjectReference: gatewayv1beta1.BackendObjectReference{
										Name: "my-service",
										Port: (*gatewayv1beta1.PortNumber)(int32p(8080)),
									},
								},
							},
						},
					},
				},
			},
		},
	},
}

var basicHTTPListeners = []model.HTTPListener{
	{
		Name: "prod-web-gw",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "my-gateway",
				Namespace: "default",
				Group:     "gateway.networking.k8s.io",
				Version:   "v1beta1",
				Kind:      "Gateway",
			},
		},
		Address:  "",
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				PathMatch: model.StringMatch{
					Prefix: "/bar",
				},
				Backends: []model.Backend{
					{
						Name:      "my-service",
						Namespace: "default",
						Port: &model.BackendPort{
							Port: 8080,
						},
					},
				},
			},
		},
	},
}

func TestGatewayAPI(t *testing.T) {

	tests := map[string]gwTestCase{
		"basic http": {
			input: basicHTTP,
			want:  basicHTTPListeners,
		},
	}

	for name, tc := range tests {

		t.Run(name, func(t *testing.T) {
			listeners := GatewayAPI(tc.input)
			assert.Equal(t, tc.want, listeners, "Listeners did not match")
		})
	}
}

func int32p(int32 int32) *int32 {
	return &int32
}

func strp(str string) *string {
	return &str
}

func pathMatchTypePtr(s string) *gatewayv1beta1.PathMatchType {
	result := gatewayv1beta1.PathMatchType(s)
	return &result
}
