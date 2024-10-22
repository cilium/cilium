// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

var meshSplitInput = GammaInput{
	Services: []corev1.Service{
		gammaEchoService,
		gammaEchoV1Service,
		gammaEchoV2Service,
	},
	HTTPRoutes: []gatewayv1.HTTPRoute{
		meshSplitHTTPRoute,
	},
}

var meshSplitListeners = []model.HTTPListener{
	{
		Name: "gateway-conformance-mesh-echo-80",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "echo",
				Namespace: "gateway-conformance-mesh",
				Version:   "v1",
				Kind:      "Service",
			},
			{
				Name:      "mesh-split",
				Namespace: "gateway-conformance-mesh",
				Version:   "v1",
				Group:     "gateway.networking.k8s.io",
				Kind:      "HTTPRoute",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{
					"*",
				},
				PathMatch: model.StringMatch{
					Exact: "/v1",
				},
				Backends: []model.Backend{
					{
						Name:      "echo-v1",
						Namespace: "gateway-conformance-mesh",
						Port: &model.BackendPort{
							Port: 80,
						},
						AppProtocol: ptr.To("http"),
					},
				},
			},
			{
				Hostnames: []string{
					"*",
				},
				PathMatch: model.StringMatch{
					Exact: "/v2",
				},
				Backends: []model.Backend{
					{
						Name:      "echo-v2",
						Namespace: "gateway-conformance-mesh",
						Port: &model.BackendPort{
							Port: 80,
						},
						AppProtocol: ptr.To("http"),
					},
				},
			},
		},
		Service: &model.Service{
			Type: "ClusterIP",
		},
	},
	{
		Name: "gateway-conformance-mesh-echo-8080",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "echo",
				Namespace: "gateway-conformance-mesh",
				Version:   "v1",
				Kind:      "Service",
			},
			{
				Name:      "mesh-split",
				Namespace: "gateway-conformance-mesh",
				Version:   "v1",
				Group:     "gateway.networking.k8s.io",
				Kind:      "HTTPRoute",
			},
		},
		Port:     8080,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{
					"*",
				},
				PathMatch: model.StringMatch{
					Exact: "/v1",
				},
				Backends: []model.Backend{
					{
						Name:      "echo-v1",
						Namespace: "gateway-conformance-mesh",
						Port: &model.BackendPort{
							Port: 80,
						},
						AppProtocol: ptr.To("http"),
					},
				},
			},
			{
				Hostnames: []string{
					"*",
				},
				PathMatch: model.StringMatch{
					Exact: "/v2",
				},
				Backends: []model.Backend{
					{
						Name:      "echo-v2",
						Namespace: "gateway-conformance-mesh",
						Port: &model.BackendPort{
							Port: 80,
						},
						AppProtocol: ptr.To("http"),
					},
				},
			},
		},
		Service: &model.Service{
			Type: "ClusterIP",
		},
	},
}

var meshPortsInput = GammaInput{
	Services: []corev1.Service{
		gammaEchoService,
		gammaEchoV1Service,
		gammaEchoV2Service,
	},
	HTTPRoutes: []gatewayv1.HTTPRoute{
		meshPortsHTTPRoute,
	},
}

var meshPortsListeners = []model.HTTPListener{
	{
		Name: "gateway-conformance-mesh-echo-v1-80",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "echo-v1",
				Namespace: "gateway-conformance-mesh",
				Version:   "v1",
				Kind:      "Service",
			},
			{
				Name:      "mesh-ports",
				Namespace: "gateway-conformance-mesh",
				Version:   "v1",
				Group:     "gateway.networking.k8s.io",
				Kind:      "HTTPRoute",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{
					"*",
				},
				Backends: []model.Backend{
					{
						Name:      "echo-v1",
						Namespace: "gateway-conformance-mesh",
						Port: &model.BackendPort{
							Port: 80,
						},
						AppProtocol: ptr.To("http"),
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set",
							Value: "v1",
						},
					},
				},
			},
		},
		Service: &model.Service{
			Type: "ClusterIP",
		},
	},
}

var meshFrontendInput = GammaInput{
	Services: []corev1.Service{
		gammaEchoService,
		gammaEchoV1Service,
		gammaEchoV2Service,
	},
	HTTPRoutes: []gatewayv1.HTTPRoute{
		meshFrontendHTTPRoute,
	},
}

var meshFrontendListeners = []model.HTTPListener{
	{
		Name: "gateway-conformance-mesh-echo-v2-80",
		Sources: []model.FullyQualifiedResource{
			{
				Name:      "echo-v2",
				Namespace: "gateway-conformance-mesh",
				Version:   "v1",
				Kind:      "Service",
			},
			{
				Name:      "mesh-split-v1",
				Namespace: "gateway-conformance-mesh",
				Version:   "v1",
				Group:     "gateway.networking.k8s.io",
				Kind:      "HTTPRoute",
			},
		},
		Port:     80,
		Hostname: "*",
		Routes: []model.HTTPRoute{
			{
				Hostnames: []string{
					"*",
				},
				Backends: []model.Backend{
					{
						Name:      "echo-v2",
						Namespace: "gateway-conformance-mesh",
						Port: &model.BackendPort{
							Port: 80,
						},
						AppProtocol: ptr.To("http"),
					},
				},
				ResponseHeaderModifier: &model.HTTPHeaderFilter{
					HeadersToSet: []model.Header{
						{
							Name:  "X-Header-Set",
							Value: "set",
						},
					},
				},
			},
		},
		Service: &model.Service{
			Type: "ClusterIP",
		},
	},
}

func TestGammaConformance(t *testing.T) {
	tests := map[string]struct {
		input GammaInput
		want  []model.HTTPListener
	}{
		"Mesh Split": {
			input: meshSplitInput,
			want:  meshSplitListeners,
		},
		"Mesh Ports": {
			input: meshPortsInput,
			want:  meshPortsListeners,
		},
		"Mesh Frontend": {
			input: meshFrontendInput,
			want:  meshFrontendListeners,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			listeners := GammaHTTPRoutes(tc.input)
			assert.Equal(t, tc.want, listeners, "Listeners did not match")
		})
	}
}
