// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
	mcsapicontrollers "sigs.k8s.io/mcs-api/pkg/controllers"
)

var (
	httpRFFinalizer = "batch.gateway.io/finalizer"

	crdsFixture = []client.Object{
		// Minimal ServiceImport CRD for existence checking
		&apiextensionsv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: "serviceimports.multicluster.x-k8s.io",
			},
			Spec: apiextensionsv1.CustomResourceDefinitionSpec{
				Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
					Name: "v1alpha1",
				}},
			},
		},
	}

	httpRouteServiceImportFixture = []client.Object{
		// Service for valid HTTPRoute
		&mcsapiv1alpha1.ServiceImport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-backend",
				Namespace: "default",
				Annotations: map[string]string{
					mcsapicontrollers.DerivedServiceAnnotation: "dummy-backend",
				},
			},
		},

		// Service in another namespace
		&mcsapiv1alpha1.ServiceImport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-backend",
				Namespace: "another-namespace",
				Annotations: map[string]string{
					mcsapicontrollers.DerivedServiceAnnotation: "dummy-backend",
				},
			},
		},

		// Service for reference grant in another namespace
		&mcsapiv1alpha1.ServiceImport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-backend-grant",
				Namespace: "another-namespace",
				Annotations: map[string]string{
					mcsapicontrollers.DerivedServiceAnnotation: "dummy-backend-grant",
				},
			},
		},

		// ServiceImport with Service that doesn't exists
		&mcsapiv1alpha1.ServiceImport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-backend-no-svc",
				Namespace: "default",
				Annotations: map[string]string{
					mcsapicontrollers.DerivedServiceAnnotation: "nonexistent-derived-svc",
				},
			},
		},
		&mcsapiv1alpha1.ServiceImport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-backend-no-svc-annotation",
				Namespace: "default",
			},
		},
	}

	httpRouteFixture = []client.Object{
		// GatewayClass
		&gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cilium",
			},
			Spec: gatewayv1.GatewayClassSpec{
				ControllerName: "io.cilium/gateway-controller",
			},
		},

		// Gateway for valid HTTPRoute
		&gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-gateway",
				Namespace: "default",
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "cilium",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "http",
						Port:     80,
						Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
					},
				},
			},
			Status: gatewayv1.GatewayStatus{},
		},

		// Gateway for valid HTTPRoute with hostnames
		&gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-gateway-hostnames",
				Namespace: "default",
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "cilium",
				Listeners: []gatewayv1.Listener{
					{
						Name:     "http",
						Port:     80,
						Hostname: ptr.To[gatewayv1.Hostname]("bar.foo.com"),
					},
				},
			},
			Status: gatewayv1.GatewayStatus{},
		},

		// Gateway in another namespace
		&gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-gateway",
				Namespace: "another-namespace",
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "cilium",
				Listeners: []gatewayv1.Listener{
					{
						Name: "http",
						Port: 80,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: ptr.To(gatewayv1.NamespacesFromSame),
							},
						},
					},
				},
			},
			Status: gatewayv1.GatewayStatus{},
		},

		// Gateway in default namespace
		&gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-gateway-two-listeners",
				Namespace: "default",
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "cilium",
				Listeners: []gatewayv1.Listener{
					{
						Name: "http",
						Port: 80,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: ptr.To(gatewayv1.NamespacesFromSame),
							},
						},
					},
					{
						Name: "https",
						Port: 443,
						AllowedRoutes: &gatewayv1.AllowedRoutes{
							Namespaces: &gatewayv1.RouteNamespaces{
								From: ptr.To(gatewayv1.NamespacesFromAll),
							},
						},
					},
				},
			},
			Status: gatewayv1.GatewayStatus{},
		},
		// Service for valid HTTPRoute
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-backend",
				Namespace: "default",
			},
		},

		// Service in another namespace
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-backend",
				Namespace: "another-namespace",
			},
		},

		// Service for reference grant in another namespace
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy-backend-grant",
				Namespace: "another-namespace",
			},
		},

		// Deleting HTTPRoute
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "deleting-http-route",
				Namespace:         "default",
				Finalizers:        []string{httpRFFinalizer},
				DeletionTimestamp: &metav1.Time{Time: time.Now()},
			},
			Spec: gatewayv1.HTTPRouteSpec{},
		},

		// Valid HTTPRoute
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "valid-http-route-service",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "dummy-backend",
										Port: ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// Valid HTTPRoute with Hostnames
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "valid-http-route-hostname-service",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				Hostnames: []gatewayv1.Hostname{
					"bar.foo.com",
				},
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway-hostnames",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "dummy-backend",
										Port: ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// Valid HTTPRoute with Hostnames
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "valid-http-route-hostname-serviceimport",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				Hostnames: []gatewayv1.Hostname{
					"bar.foo.com",
				},
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway-hostnames",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "dummy-backend",
										Port: ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Group: GroupPtr(mcsapiv1alpha1.GroupName),
										Kind:  KindPtr("ServiceImport"),
										Name:  "dummy-backend",
										Port:  ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "valid-http-route-serviceimport",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "dummy-backend",
										Port: ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Group: GroupPtr(mcsapiv1alpha1.GroupName),
										Kind:  KindPtr("ServiceImport"),
										Name:  "dummy-backend",
										Port:  ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// HTTPRoute with nonexistent backend
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-nonexistent-svc",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "nonexistent-backend",
										Port: ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-nonexistent-svcimport",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Group: GroupPtr(mcsapiv1alpha1.GroupName),
										Kind:  KindPtr("ServiceImport"),
										Name:  "nonexistent-backend",
										Port:  ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-nonexistent-svcimport-svc",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Group: GroupPtr(mcsapiv1alpha1.GroupName),
										Kind:  KindPtr("ServiceImport"),
										Name:  "dummy-backend-no-svc",
										Port:  ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-nonexistent-svcimport-svc-annotation",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Group: GroupPtr(mcsapiv1alpha1.GroupName),
										Kind:  KindPtr("ServiceImport"),
										Name:  "dummy-backend-no-svc-annotation",
										Port:  ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// HTTPRoute with cross namespace backend
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-cross-namespace-service",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name:      "dummy-backend",
										Namespace: ptr.To[gatewayv1.Namespace]("another-namespace"),
									},
								},
							},
						},
					},
				},
			},
		},
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-cross-namespace-serviceimport",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Group:     GroupPtr(mcsapiv1alpha1.GroupName),
										Kind:      KindPtr("ServiceImport"),
										Name:      "dummy-backend",
										Namespace: ptr.To[gatewayv1.Namespace]("another-namespace"),
										Port:      ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},
		// HTTPRoute with cross namespace listener
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-cross-namespace-listener",
				Namespace: "another-namespace",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name:      "dummy-gateway-two-listeners",
							Namespace: ptr.To[gatewayv1.Namespace]("default"),
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name:      "dummy-backend",
										Namespace: ptr.To[gatewayv1.Namespace]("another-namespace"),
										Port:      ptr.To(gatewayv1.PortNumber(8080)),
									},
								},
							},
						},
					},
				},
			},
		},
		// HTTPRoute with hostnames and cross namespace listener
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-hostnames-and-cross-namespace-listener",
				Namespace: "another-namespace",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				Hostnames: []gatewayv1.Hostname{
					"bar.foo.com",
				},
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name:      "dummy-gateway-two-listeners",
							Namespace: ptr.To[gatewayv1.Namespace]("default"),
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name:      "dummy-backend",
										Namespace: ptr.To[gatewayv1.Namespace]("another-namespace"),
										Port:      ptr.To(gatewayv1.PortNumber(8080)),
									},
								},
							},
						},
					},
				},
			},
		},
		// HTTPRoute with cross namespace backend
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-cross-namespace-backend-with-grant",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name:      "dummy-backend-grant",
										Namespace: ptr.To[gatewayv1.Namespace]("another-namespace"),
										Port:      ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Group:     GroupPtr(mcsapiv1alpha1.GroupName),
										Kind:      KindPtr("ServiceImport"),
										Name:      "dummy-backend-grant",
										Namespace: ptr.To[gatewayv1.Namespace]("another-namespace"),
										Port:      ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// ReferenceGrant to allow "http-route-with-cross-namespace-backend-with-grant
		&gatewayv1beta1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-service-from-default",
				Namespace: "another-namespace",
			},
			Spec: gatewayv1beta1.ReferenceGrantSpec{
				From: []gatewayv1beta1.ReferenceGrantFrom{
					{
						Group:     "gateway.networking.k8s.io",
						Kind:      "HTTPRoute",
						Namespace: "default",
					},
				},
				To: []gatewayv1beta1.ReferenceGrantTo{
					{
						Group: "",
						Kind:  "Service",
						Name:  ObjectNamePtr("dummy-backend-grant"),
					},
				},
			},
		},
		&gatewayv1beta1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-service-import-from-default",
				Namespace: "another-namespace",
			},
			Spec: gatewayv1beta1.ReferenceGrantSpec{
				From: []gatewayv1beta1.ReferenceGrantFrom{
					{
						Group:     "gateway.networking.k8s.io",
						Kind:      "HTTPRoute",
						Namespace: "default",
					},
				},
				To: []gatewayv1beta1.ReferenceGrantTo{
					{
						Group: mcsapiv1alpha1.GroupName,
						Kind:  "ServiceImport",
						Name:  ObjectNamePtr("dummy-backend-grant"),
					},
				},
			},
		},

		// HTTPRoute with unsupported backend
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-unsupported-backend",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name:  "unsupported-backend",
										Group: GroupPtr("unsupported-group"),
										Kind:  KindPtr("UnsupportedKind"),
									},
								},
							},
						},
					},
				},
			},
		},
		// HTTPRoute missing port for Service and ServiceImport
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-missing-port-for-backend-service",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name:  "missing-port-service-backend",
										Group: GroupPtr(""),
										Kind:  KindPtr("Service"),
									},
								},
							},
						},
					},
				},
			},
		},
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-missing-port-for-backend-serviceimport",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Group: GroupPtr(mcsapiv1alpha1.GroupName),
										Kind:  KindPtr("ServiceImport"),
										Name:  "missing-port-service-backend",
									},
								},
							},
						},
					},
				},
			},
		},

		// HTTPRoute with non-existent gateway
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-nonexistent-gateway",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "non-existent-gateway",
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "dummy-backend",
										Port: ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// HTTPRoute with valid but not allowed gateway
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-not-allowed-gateway",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name:      "dummy-gateway",
							Namespace: ptr.To[gatewayv1.Namespace]("another-namespace"),
						},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "dummy-backend",
										Port: ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},

		// HTTPRoute with non-matching hostname with gateway listener
		&gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "http-route-with-non-matching-hostname",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{
							Name: "dummy-gateway",
						},
					},
				},
				Hostnames: []gatewayv1.Hostname{
					"non-matching-hostname",
				},
				Rules: []gatewayv1.HTTPRouteRule{
					{
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "dummy-backend",
										Port: ptr.To[gatewayv1.PortNumber](8080),
									},
								},
							},
						},
					},
				},
			},
		},
	}
)

func Test_httpRouteReconciler_Reconcile(t *testing.T) {
	scheme := testScheme()
	mcsapiv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(crdsFixture...).
		WithObjects(httpRouteFixture...).
		WithObjects(httpRouteServiceImportFixture...).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		Build()

	r := &httpRouteReconciler{Client: c, logger: hivetest.Logger(t)}

	t.Run("no http route", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "non-existing-http-route",
				Namespace: "default",
			},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)
	})

	t.Run("http route exists but being deleted", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "deleting-http-route",
				Namespace: "default",
			},
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")
	})

	t.Run("valid http route", func(t *testing.T) {
		for _, name := range []string{"service", "serviceimport"} {
			key := types.NamespacedName{
				Name:      "valid-http-route-" + name,
				Namespace: "default",
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err, "Error reconciling httpRoute")
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			route := &gatewayv1.HTTPRoute{}
			err = c.Get(context.Background(), key, route)

			require.NoError(t, err)
			require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
			require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

			require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
			require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

			require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
			require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
		}
	})

	t.Run("valid http route and hostname matches", func(t *testing.T) {
		for _, name := range []string{"service", "serviceimport"} {
			key := types.NamespacedName{
				Name:      "valid-http-route-hostname-" + name,
				Namespace: "default",
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err, "Error reconciling httpRoute")
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			route := &gatewayv1.HTTPRoute{}
			err = c.Get(context.Background(), key, route)

			require.NoError(t, err)
			require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
			require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

			require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
			require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
			require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
			require.Equal(t, "Accepted HTTPRoute", route.Status.RouteStatus.Parents[0].Conditions[0].Message)

			require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
			require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
		}
	})

	t.Run("valid http route and hostname matches cross-namespace", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-hostnames-and-cross-namespace-listener",
			Namespace: "another-namespace",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
		require.Equal(t, "Accepted HTTPRoute", route.Status.RouteStatus.Parents[0].Conditions[0].Message)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
	})

	t.Run("http route with nonexistent backend", func(t *testing.T) {
		for _, name := range []string{"svc", "svcimport", "svcimport-svc", "svcimport-svc-annotation"} {
			key := types.NamespacedName{
				Name:      "http-route-with-nonexistent-" + name,
				Namespace: "default",
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err, "Error reconciling httpRoute")
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			route := &gatewayv1.HTTPRoute{}
			err = c.Get(context.Background(), key, route)

			require.NoError(t, err)
			require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
			require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

			require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
			require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

			require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
			require.Equal(t, "BackendNotFound", route.Status.RouteStatus.Parents[0].Conditions[1].Reason)
		}
	})

	t.Run("http route with nonexistent gateway", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-nonexistent-gateway",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "InvalidHTTPRoute", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
	})

	t.Run("http route with valid but not allowed gateway", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-not-allowed-gateway",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "NotAllowedByListeners", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
		require.Equal(t, "HTTPRoute is not allowed to attach to this Gateway due to namespace restrictions", route.Status.RouteStatus.Parents[0].Conditions[0].Message)

		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)
		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
	})

	t.Run("http route with non-matching hostname", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-non-matching-hostname",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)
		require.Equal(t, "NoMatchingListenerHostname", route.Status.RouteStatus.Parents[0].Conditions[0].Reason)
		require.Equal(t, "No matching listener hostname", route.Status.RouteStatus.Parents[0].Conditions[0].Message)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
	})

	t.Run("http route with cross namespace backend", func(t *testing.T) {
		for _, name := range []string{"service", "serviceimport"} {
			key := types.NamespacedName{
				Name:      "http-route-with-cross-namespace-" + name,
				Namespace: "default",
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err, "Error reconciling httpRoute")
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			route := &gatewayv1.HTTPRoute{}
			err = c.Get(context.Background(), key, route)

			require.NoError(t, err)
			require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
			require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

			require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
			require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

			require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
			require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
			require.Equal(t, "RefNotPermitted", route.Status.RouteStatus.Parents[0].Conditions[1].Reason)
			require.Equal(t, "Cross namespace references are not allowed", route.Status.RouteStatus.Parents[0].Conditions[1].Message)
		}
	})

	t.Run("http route with cross namespace listener", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-cross-namespace-listener",
			Namespace: "another-namespace",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
	})

	t.Run("http route with cross namespace backend with reference grant", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-cross-namespace-backend-with-grant",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
	})

	t.Run("http route with un-supported backend", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "http-route-with-unsupported-backend",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
		require.Equal(t, "InvalidKind", route.Status.RouteStatus.Parents[0].Conditions[1].Reason)
		require.Equal(t, "Unsupported backend kind UnsupportedKind", route.Status.RouteStatus.Parents[0].Conditions[1].Message)
	})

	t.Run("http route missing port of Service backend", func(t *testing.T) {
		for _, name := range []string{"service", "serviceimport"} {
			key := types.NamespacedName{
				Name:      "http-route-missing-port-for-backend-" + name,
				Namespace: "default",
			}
			result, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: key,
			})

			require.NoError(t, err, "Error reconciling httpRoute")
			require.Equal(t, ctrl.Result{}, result, "Result should be empty")

			route := &gatewayv1.HTTPRoute{}
			err = c.Get(context.Background(), key, route)

			require.NoError(t, err)
			require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
			require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

			require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
			require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

			require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
			require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
			require.Equal(t, "InvalidKind", route.Status.RouteStatus.Parents[0].Conditions[1].Reason)
			require.Equal(t, "Must have port for backend object reference", route.Status.RouteStatus.Parents[0].Conditions[1].Message)
		}
	})
}

func Test_httpRouteReconciler_Reconcile_NoServiceImportCRD(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(httpRouteFixture...).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		Build()

	r := &httpRouteReconciler{Client: c, logger: hivetest.Logger(t)}

	t.Run("valid http route with Service", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "valid-http-route-service",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
	})

	t.Run("valid http route with ServiceImport", func(t *testing.T) {
		key := types.NamespacedName{
			Name:      "valid-http-route-serviceimport",
			Namespace: "default",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err, "Error reconciling httpRoute")
		require.Equal(t, ctrl.Result{}, result, "Result should be empty")

		route := &gatewayv1.HTTPRoute{}
		err = c.Get(context.Background(), key, route)

		require.NoError(t, err)
		require.Len(t, route.Status.RouteStatus.Parents, 1, "Should have 1 parent")
		require.Len(t, route.Status.RouteStatus.Parents[0].Conditions, 2)

		require.Equal(t, "Accepted", route.Status.RouteStatus.Parents[0].Conditions[0].Type)
		require.Equal(t, metav1.ConditionStatus("True"), route.Status.RouteStatus.Parents[0].Conditions[0].Status)

		require.Equal(t, "ResolvedRefs", route.Status.RouteStatus.Parents[0].Conditions[1].Type)
		require.Equal(t, metav1.ConditionStatus("False"), route.Status.RouteStatus.Parents[0].Conditions[1].Status)
		require.Equal(t, "BackendNotFound", route.Status.RouteStatus.Parents[0].Conditions[1].Reason)
		require.Equal(t, "serviceimports.multicluster.x-k8s.io \"dummy-backend\" not found",
			route.Status.RouteStatus.Parents[0].Conditions[1].Message)
	})
}
