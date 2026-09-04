// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loading

import (
	"log/slog"
	"testing"

	mcsapicontrollers "sigs.k8s.io/mcs-api/controllers"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
)

func TestLoadLoadsOnlyReferencedServices(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gw",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
		},
	}

	gwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
	}

	httpRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-route",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: gatewayv1.ObjectName(gw.Name)},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("backend-service"),
									Port: ptr.To[gatewayv1.PortNumber](80),
								},
							},
						},
					},
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterRequestMirror,
							RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
								BackendRef: gatewayv1.BackendObjectReference{
									Group: ptr.To[gatewayv1.Group](mcsapiv1beta1.GroupName),
									Kind:  ptr.To[gatewayv1.Kind]("ServiceImport"),
									Name:  gatewayv1.ObjectName("mirror-serviceimport"),
									Port:  ptr.To[gatewayv1.PortNumber](8080),
								},
							},
						},
					},
				},
			},
		},
	}

	unrelatedHTTPRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unrelated-http-route",
			Namespace: "other",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "other-gw"},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("unrelated-route-service"),
									Port: ptr.To[gatewayv1.PortNumber](80),
								},
							},
						},
					},
				},
			},
		},
	}

	backendService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-service",
			Namespace: "default",
		},
	}

	mirrorService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mirror-service",
			Namespace: "default",
		},
	}

	unrelatedService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unrelated-service",
			Namespace: "default",
		},
	}

	serviceImport := &mcsapiv1beta1.ServiceImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mirror-serviceimport",
			Namespace: "default",
			Annotations: map[string]string{
				mcsapicontrollers.DerivedServiceAnnotation: "mirror-service",
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithObjects(
			gw,
			gwc,
			httpRoute,
			unrelatedHTTPRoute,
			backendService,
			mirrorService,
			unrelatedService,
			serviceImport,
		).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.GatewayHTTPRouteIndex, indexers.IndexHTTPRouteByGateway).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.GatewayGRPCRouteIndex, indexers.IndexGRPCRouteByGateway).
		WithIndex(&gatewayv1.TLSRoute{}, indexers.GatewayTLSRouteIndex, indexers.IndexTLSRouteByGateway).
		Build()

	loader := NewTranslationInputLoader(c, logger, "io.cilium/gateway-controller", TranslationInputLoaderConfig{
		IncludeServiceImports: true,
	})

	inputs, err := loader.Load(t.Context(), logger, gw, gwc)
	require.NoError(t, err)

	require.Len(t, inputs.Services, 2)
	require.Equal(t, []client.ObjectKey{
		{Namespace: "default", Name: "backend-service"},
		{Namespace: "default", Name: "mirror-service"},
	}, serviceKeys(inputs.Services))
}

func serviceKeys(services []corev1.Service) []client.ObjectKey {
	keys := make([]client.ObjectKey, 0, len(services))
	for _, svc := range services {
		keys = append(keys, client.ObjectKeyFromObject(&svc))
	}
	return keys
}
