// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
)

var gwFixture = []client.Object{
	// Valid Gateway class
	&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "io.cilium/gateway-controller",
		},
	},

	// Service for valid HTTPRoute
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dummy-backend",
			Namespace: "default",
		},
	},
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cilium-gateway-valid-gateway",
			Namespace: "another-namespace",
			Annotations: map[string]string{
				"pre-existing-annotation": "true",
			},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{
						IP: "10.10.10.11",
						Ports: []corev1.PortStatus{
							{
								Port:     80,
								Protocol: "TCP",
							},
						},
					},
				},
			},
		},
	},
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cilium-gateway-valid-gateway",
			Namespace: "default",
			Annotations: map[string]string{
				"pre-existing-annotation": "true",
			},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{
						IP: "10.10.10.10",
						Ports: []corev1.PortStatus{
							{
								Port:     80,
								Protocol: "TCP",
							},
						},
					},
				},
			},
		},
	},
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cilium-gateway-test-long-long-long-long-long-long-lo-8tfth549c6",
			Namespace: "long-name-test",
			Annotations: map[string]string{
				"pre-existing-annotation": "true",
			},
		},
	},

	// Service in another namespace
	&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dummy-backend",
			Namespace: "another-namespace",
		},
	},

	// Valid HTTPRoute
	&gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "http-route",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: "valid-gateway",
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
									Port: ptr.To[gatewayv1.PortNumber](80),
								},
							},
						},
					},
				},
			},
		},
		Status: gatewayv1.HTTPRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{
					{
						ParentRef: gatewayv1.ParentReference{
							Name: "valid-gateway",
						},
						ControllerName: "io.cilium/gateway-controller",
						Conditions: []metav1.Condition{
							{
								Type:   "Accepted",
								Status: "True",
							},
						},
					},
				},
			},
		},
	},

	// Valid gateway
	&gatewayv1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1.GroupName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
					Protocol: "HTTP",
				},
			},
		},
	},
	// Valid gateway
	&gatewayv1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1.GroupName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-long-long-long-long-long-long-long-long-long-long-long-long-name",
			Namespace: "long-name-test",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
					Protocol: "HTTP",
				},
			},
		},
	},
	// gateway with non-existent gateway class
	&gatewayv1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1.GroupName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-with-non-existent-gateway-class",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "non-existent-gateway-class",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
					Protocol: "HTTP",
				},
			},
		},
	},

	/// Valid TLSRoute gateway
	&gatewayv1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1.GroupName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-tlsroute-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls",
					Port:     443,
					Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.rocks"),
					Protocol: "TLS",
				},
			},
		},
	},
}

var tlsRouteFixtures = []client.Object{
	// Valid TLSRoute
	&gatewayv1alpha2.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-route",
			Namespace: "default",
		},
		Spec: gatewayv1alpha2.TLSRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: "valid-tlsroute-gateway",
					},
				},
			},
			Hostnames: []gatewayv1alpha2.Hostname{
				"sni.cilium.rocks",
			},
			Rules: []gatewayv1alpha2.TLSRouteRule{
				{
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "dummy-backend",
								Port: ptr.To[gatewayv1.PortNumber](443),
							},
						},
					},
				},
			},
		},
		Status: gatewayv1alpha2.TLSRouteStatus{
			RouteStatus: gatewayv1.RouteStatus{
				Parents: []gatewayv1.RouteParentStatus{
					{
						ParentRef: gatewayv1.ParentReference{
							Name: "valid-tlsroute-gateway",
						},
						ControllerName: "io.cilium/gateway-controller",
						Conditions: []metav1.Condition{
							{
								Type:   "Accepted",
								Status: "True",
							},
						},
					},
				},
			},
		},
	},
}

func Test_gatewayReconciler_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(gwFixture...).
		WithObjects(tlsRouteFixtures...).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		Build()

	logger := hivetest.Logger(t)

	cecTranslator := translation.NewCECTranslator("", false, false, true, 60, false, nil, false, false, 0)
	gatewayAPITranslator := gatewayApiTranslation.NewTranslator(cecTranslator, false, string(corev1.ServiceExternalTrafficPolicyCluster))

	r := &gatewayReconciler{
		Client:     c,
		translator: gatewayAPITranslator,
		logger:     logger,
	}

	t.Run("non-existent gateway", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: client.ObjectKey{
				Namespace: "default",
				Name:      "non-existent-gateway",
			},
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)
	})

	t.Run("non-existent gateway class", func(t *testing.T) {
		key := client.ObjectKey{
			Namespace: "default",
			Name:      "gateway-with-non-existent-gateway-class",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: key,
		})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)
	})

	t.Run("valid http gateway", func(t *testing.T) {
		key := client.ObjectKey{
			Namespace: "default",
			Name:      "valid-gateway",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})

		// First reconcile should wait for LB status before writing addresses into Ingress status
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		gw := &gatewayv1.Gateway{}
		err = c.Get(context.Background(), key, gw)
		require.NoError(t, err)

		// Check that the gateway status has been updated
		err = c.Get(context.Background(), key, gw)
		require.NoError(t, err)

		require.Len(t, gw.Status.Conditions, 2)
		require.Equal(t, "Accepted", gw.Status.Conditions[0].Type)
		require.Equal(t, "True", string(gw.Status.Conditions[0].Status))
		require.Equal(t, "Gateway successfully scheduled", gw.Status.Conditions[0].Message)
		require.Equal(t, "Programmed", gw.Status.Conditions[1].Type)
		require.Equal(t, "True", string(gw.Status.Conditions[1].Status))
		require.Equal(t, "Gateway successfully reconciled", gw.Status.Conditions[1].Message)

		require.Len(t, gw.Status.Addresses, 1)
		require.Equal(t, "IPAddress", string(*gw.Status.Addresses[0].Type))
		require.Equal(t, "10.10.10.10", gw.Status.Addresses[0].Value)

		require.Len(t, gw.Status.Listeners, 1)
		require.Equal(t, "http", string(gw.Status.Listeners[0].Name))
		require.Len(t, gw.Status.Listeners[0].Conditions, 3)
		require.Equal(t, "Programmed", gw.Status.Listeners[0].Conditions[0].Type)
		require.Equal(t, "True", string(gw.Status.Listeners[0].Conditions[0].Status))
		require.Equal(t, "Programmed", gw.Status.Listeners[0].Conditions[0].Reason)
		require.Equal(t, "Listener Programmed", gw.Status.Listeners[0].Conditions[0].Message)
		require.Equal(t, "Accepted", gw.Status.Listeners[0].Conditions[1].Type)
		require.Equal(t, "True", string(gw.Status.Listeners[0].Conditions[1].Status))
		require.Equal(t, "ResolvedRefs", gw.Status.Listeners[0].Conditions[2].Type)
		require.Equal(t, "True", string(gw.Status.Listeners[0].Conditions[2].Status))
	})

	t.Run("valid http gateway - long name", func(t *testing.T) {
		key := client.ObjectKey{
			Namespace: "long-name-test",
			Name:      "test-long-long-long-long-long-long-long-long-long-long-long-long-name",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})

		// First reconcile should wait for LB status before writing addresses into Ingress status
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		gw := &gatewayv1.Gateway{}
		err = c.Get(context.Background(), key, gw)
		require.NoError(t, err)
		require.Empty(t, gw.Status.Addresses)

		// Simulate LB service update
		lb := &corev1.Service{}
		err = c.Get(context.Background(), client.ObjectKey{Namespace: "long-name-test", Name: "cilium-gateway-test-long-long-long-long-long-long-lo-8tfth549c6"}, lb)
		require.NoError(t, err)
		require.Equal(t, corev1.ServiceTypeLoadBalancer, lb.Spec.Type)
		require.Equal(t, "test-long-long-long-long-long-long-long-long-long-lo-4bftbgh5ht", lb.Labels["io.cilium.gateway/owning-gateway"])
		require.Equal(t, "true", lb.Annotations["pre-existing-annotation"])

		// Update LB status
		lb.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
			{
				IP: "10.10.10.20",
				Ports: []corev1.PortStatus{
					{
						Port:     80,
						Protocol: "TCP",
					},
				},
			},
		}
		err = c.Status().Update(context.Background(), lb)
		require.NoError(t, err)

		// Perform second reconciliation
		result, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		// Check that the gateway status has been updated
		err = c.Get(context.Background(), key, gw)
		require.NoError(t, err)

		require.Len(t, gw.Status.Conditions, 2)
		require.Equal(t, "Accepted", gw.Status.Conditions[0].Type)
		require.Equal(t, "True", string(gw.Status.Conditions[0].Status))
		require.Equal(t, "Gateway successfully scheduled", gw.Status.Conditions[0].Message)
		require.Equal(t, "Programmed", gw.Status.Conditions[1].Type)
		require.Equal(t, "True", string(gw.Status.Conditions[1].Status))
		require.Equal(t, "Gateway successfully reconciled", gw.Status.Conditions[1].Message)

		require.Len(t, gw.Status.Addresses, 1)
		require.Equal(t, "IPAddress", string(*gw.Status.Addresses[0].Type))
		require.Equal(t, "10.10.10.20", gw.Status.Addresses[0].Value)

		require.Len(t, gw.Status.Listeners, 1)
		require.Equal(t, "http", string(gw.Status.Listeners[0].Name))
		require.Len(t, gw.Status.Listeners[0].Conditions, 3)
		require.Equal(t, "Programmed", gw.Status.Listeners[0].Conditions[0].Type)
		require.Equal(t, "True", string(gw.Status.Listeners[0].Conditions[0].Status))
		require.Equal(t, "Programmed", gw.Status.Listeners[0].Conditions[0].Reason)
		require.Equal(t, "Listener Programmed", gw.Status.Listeners[0].Conditions[0].Message)
		require.Equal(t, "Accepted", gw.Status.Listeners[0].Conditions[1].Type)
		require.Equal(t, "True", string(gw.Status.Listeners[0].Conditions[1].Status))
		require.Equal(t, "ResolvedRefs", gw.Status.Listeners[0].Conditions[2].Type)
		require.Equal(t, "True", string(gw.Status.Listeners[0].Conditions[2].Status))
	})

	t.Run("valid tls gateway", func(t *testing.T) {
		key := client.ObjectKey{
			Namespace: "default",
			Name:      "valid-tlsroute-gateway",
		}
		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})

		// First reconcile should wait for LB status before writing addresses into Ingress status
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		gw := &gatewayv1.Gateway{}
		err = c.Get(context.Background(), key, gw)
		require.NoError(t, err)
		require.Empty(t, gw.Status.Addresses)

		// Simulate LB service update
		lb := &corev1.Service{}
		err = c.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "cilium-gateway-valid-tlsroute-gateway"}, lb)
		require.NoError(t, err)
		require.Equal(t, corev1.ServiceTypeLoadBalancer, lb.Spec.Type)
		require.Equal(t, "valid-tlsroute-gateway", lb.Labels["io.cilium.gateway/owning-gateway"])

		// Update LB status
		lb.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
			{
				IP: "10.10.10.11",
				Ports: []corev1.PortStatus{
					{
						Port:     443,
						Protocol: "TCP",
					},
				},
			},
		}
		err = c.Status().Update(context.Background(), lb)
		require.NoError(t, err)

		// Perform second reconciliation
		result, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		// Check that the gateway status has been updated
		err = c.Get(context.Background(), key, gw)
		require.NoError(t, err)

		require.Len(t, gw.Status.Conditions, 2)
		require.Equal(t, "Accepted", gw.Status.Conditions[0].Type)
		require.Equal(t, "True", string(gw.Status.Conditions[0].Status))
		require.Equal(t, "Gateway successfully scheduled", gw.Status.Conditions[0].Message)
		require.Equal(t, "Programmed", gw.Status.Conditions[1].Type)
		require.Equal(t, "True", string(gw.Status.Conditions[1].Status))
		require.Equal(t, "Gateway successfully reconciled", gw.Status.Conditions[1].Message)

		require.Len(t, gw.Status.Addresses, 1)
		require.Equal(t, "IPAddress", string(*gw.Status.Addresses[0].Type))
		require.Equal(t, "10.10.10.11", gw.Status.Addresses[0].Value)

		require.Len(t, gw.Status.Listeners, 1)
		require.Equal(t, "tls", string(gw.Status.Listeners[0].Name))
		require.Len(t, gw.Status.Listeners[0].Conditions, 3)
		require.Equal(t, "Programmed", gw.Status.Listeners[0].Conditions[0].Type)
		require.Equal(t, "True", string(gw.Status.Listeners[0].Conditions[0].Status))
		require.Equal(t, "Programmed", gw.Status.Listeners[0].Conditions[0].Reason)
		require.Equal(t, "Listener Programmed", gw.Status.Listeners[0].Conditions[0].Message)
		require.Equal(t, "Accepted", gw.Status.Listeners[0].Conditions[1].Type)
		require.Equal(t, "True", string(gw.Status.Listeners[0].Conditions[1].Status))
		require.Equal(t, "ResolvedRefs", gw.Status.Listeners[0].Conditions[2].Type)
		require.Equal(t, "True", string(gw.Status.Listeners[0].Conditions[2].Status))
	})
}

func Test_isValidPemFormat(t *testing.T) {
	cert := []byte(`-----BEGIN CERTIFICATE-----
MIIENDCCApygAwIBAgIRAKD/BLFBfwKIZ0WGrHtTH6gwDQYJKoZIhvcNAQELBQAw
dzEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMSYwJAYDVQQLDB10YW1t
YWNoQGZlZG9yYS5sYW4gKFRhbSBNYWNoKTEtMCsGA1UEAwwkbWtjZXJ0IHRhbW1h
Y2hAZmVkb3JhLmxhbiAoVGFtIE1hY2gpMB4XDTIzMDIyMTExMDg0M1oXDTI1MDUy
MTEyMDg0M1owUTEnMCUGA1UEChMebWtjZXJ0IGRldmVsb3BtZW50IGNlcnRpZmlj
YXRlMSYwJAYDVQQLDB10YW1tYWNoQGZlZG9yYS5sYW4gKFRhbSBNYWNoKTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIZy+0JRVjqpWgeq2dP+1oliO4A
CcZnMg4tSqPalhDQL6Mf68HYLfizyJIpRzMJ905rYd0AcmXmu/g0Eo8ykHxFDz5T
sePs2XQng8MN4azsRmm1l4f74ovawQzQcb822QP1CS6ILZ3VtwNjRh2nAwthYBMo
CkngDGeQ8Gl0tjHLFnBdTdSwQRmE2jtDBcAgyEGpq+6ReYt+/47nNn7dCftsVqhE
BYr9XH3itefHmsbfj7zWFbptdko7q9lMHwnBd+0hd40MmJIXMZrOGGFZjawJDBqS
sBq2Q3l6XQz8X7P/GA8Dn8h4w3rppmiaN7LOmGXeki3xX2wqnM+0s6aZYZsCAwEA
AaNhMF8wDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB8GA1Ud
IwQYMBaAFGQ2DB06CdQFQBsYPye0NBwErUNEMBcGA1UdEQQQMA6CDHVuaXR0ZXN0
LmNvbTANBgkqhkiG9w0BAQsFAAOCAYEArtHdKWXR6aELpfal17biabCPvIF9j6nw
uDzcdMYQLrXm8M+NHe8x3dpI7u3lltO+dzLng+nVKQOR3alQACSmRD9c7ie8eT5d
7zKOTk6keY195I1wVV4jbNLbNWa9y4RJQRTvBLAvAP9NVtUw2Q/w/ErUTqSyz+ob
dwnt4gYCw6dGnluLxlfF34DB9KflvVNSnkyMB/gsB4A3r1GPOIo0Gyf74ig3FWrS
wHYKnBbtZfYO0JV0LCoPyHe8g0XajZe8DCbP/E6SmlTNAmJESVjigTTcIBAkFI+n
toBAdxfhjKUGaClOHS29cpaiynjSayGm4RkHkx7mcAua9lWPf7pSa3mCcFb+wFr3
ABkHDPJH2acfaUK1vgKTgOwcG/6KA820/PraoSihLaPK/A7eg77r1EeYpt0Neppb
XjvUp3YmVlIMZXPzrjOsastoDSrsygj5jdVtm4Pslv9nPhzDrBjlZpEJScW4Jlb+
6wtd7p03UDBSKfTbVROVAe5mvJvA0hoS
-----END CERTIFICATE-----
`)
	key := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDCGcvtCUVY6qVo
HqtnT/taJYjuAAnGZzIOLUqj2pYQ0C+jH+vB2C34s8iSKUczCfdOa2HdAHJl5rv4
NBKPMpB8RQ8+U7Hj7Nl0J4PDDeGs7EZptZeH++KL2sEM0HG/NtkD9QkuiC2d1bcD
Y0YdpwMLYWATKApJ4AxnkPBpdLYxyxZwXU3UsEEZhNo7QwXAIMhBqavukXmLfv+O
5zZ+3Qn7bFaoRAWK/Vx94rXnx5rG34+81hW6bXZKO6vZTB8JwXftIXeNDJiSFzGa
zhhhWY2sCQwakrAatkN5el0M/F+z/xgPA5/IeMN66aZomjeyzphl3pIt8V9sKpzP
tLOmmWGbAgMBAAECggEAEjASoMJ2og9Ssn/1NbgT6G2N+Cc+wz2WPifWT6ZC2452
eEWcdMyJ+jz2dWOyzUCI0OtU/z10esH1KRvQBWUKjup1tDRpfd8KvUyalyNs2yRE
sNEYQuDCaLJ11nqNvgooqatDUf3msFx/Sqz5u/uTWHSmaQUeea+p2eaF8IvEKsQf
6QNklkeHsv+GVPv+iibfbXXne6I5aV35Rc4Q08zRCgYX/BN1AYXV6ho4RC9dZVGP
JUkSLzRadegok/EONKkrqLZOFJVb2wtFq85gJ01lODM/gj7GqM59M/wk55CaQIRD
9x5H4X4rpM2rhmiNLkIN0tGLKO8X31up7hTx9bvJcQKBgQD51MLWYYUPz/umvSrN
QOT9UhEHI/bxtCbWQthW3L1qrVT7DB8Jko/6/xYlXhl7nwVwJz24jJf9vuxWbBpL
HZRf0QsDO2/O4rqhKDov/GMUCx2shzc+J7k+T93KNVANYa05guqMeB8n30HProkF
LgihVFF20k9Z6SibUvgTMpF1EwKBgQDG5MBgc8oFXmlr/7pHKizC4F3eDAXUxVHM
WCIbSwMyzOXKqDcdXNDz8cQrjhKa2rD1fKhE0oRR+QvHz8IPC+0MsT7Q6QsIHYj5
CXubHr0s5k8PJAp+Lk2EdHePZQM/I/vj/gSwxnJ9Qs64FWZ25K9zYnNNsiojQel7
WVmI9IVaWQKBgD3BYggsQwANoV8uE455JCGaT6s8MKa+qXr9Owz9s7TS89a6wFFV
cVHSDF9gS1xLisSWbqNX3ZpTv4f9YOKAhVTKD7bU0maJlSiREREbikJCHSuwoO80
Uo4cn+6EDy2/n1pACkp+xvTMMzBrLGOjZW67sQd2JTdMc0Ux1TCpp1sRAoGAaEVI
rchGYyYp8pqw19o+eTQTQfPforqHta+GwfRDiwBsgCBMNLKSQTHAfG0RR+na1/gw
Z1ROVoNQL8K1pBnGft71ZaSnSeviAV19Vcd5ue5MCE4GyjwQG57Lh3uXhiShS9fC
McL4Br9djJh7jV06ti0o8dSzzqQhea9QB0LaHpECgYApc8oBoiK69s0wXyI4+Phx
ScBJ0XqDBYFkxyXr8Y5pEarEaqCtl1OPPMOiQRDWoxRR+FwA/0laSfh5xw0U3b+q
iZ2XpkrbQp034rC0UR6p+Km1Sv9AVCACAjrcQ3NZaf8bDOWqvpla7Auq0oG8i6UX
hEKCKf/N3gE1oMrTxVzUDQ==
-----END PRIVATE KEY-----
`)
	keyAndCert := append(key, cert...)
	type args struct {
		b []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "valid cert pem",
			args: args{
				b: cert,
			},
			want: true,
		},
		{
			name: "value key pem",
			args: args{
				b: key,
			},
			want: true,
		},
		{
			name: "multiple valid pem blocks",
			args: args{
				b: keyAndCert,
			},
			want: true,
		},
		{
			name: "invalid first block",
			args: args{
				b: append([]byte("invalid block"), key...),
			},
			want: false,
		},
		{
			name: "invalid subsequent block",
			args: args{
				b: append(keyAndCert, []byte("invalid block")...),
			},
			want: false,
		},
		{
			name: "invalid pem",
			args: args{
				b: []byte("invalid pem"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, isValidPemFormat(tt.args.b), "isValidPemFormat(%v)", tt.args.b)
		})
	}
}

func Test_sectionNameMatched(t *testing.T) {
	httpListener := &gatewayv1.Listener{
		Name:     "http",
		Port:     80,
		Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
		Protocol: "HTTP",
	}
	httpNoMatchListener := &gatewayv1.Listener{
		Name:     "http-no-match",
		Port:     8080,
		Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
		Protocol: "HTTP",
	}
	gw := &gatewayv1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1.GroupName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				*httpListener,
				*httpNoMatchListener,
			},
		},
	}
	type args struct {
		routeNamespace string
		listener       *gatewayv1.Listener
		refs           []gatewayv1.ParentReference
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Matching Section name",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name:        "valid-gateway",
						SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
					},
				},
			},
			want: true,
		},
		{
			name: "Not matching Section name",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name:        "valid-gateway",
						SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
					},
				},
			},
			want: false,
		},
		{
			name: "Matching Port number",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
						Port: (*gatewayv1.PortNumber)(ptr.To[int32](80)),
					},
				},
			},
			want: true,
		},
		{
			name: "No matching Port number",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
						Port: (*gatewayv1.PortNumber)(ptr.To[int32](80)),
					},
				},
			},
			want: false,
		},
		{
			name: "Matching both Section name and Port number",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name:        "valid-gateway",
						SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
						Port:        (*gatewayv1.PortNumber)(ptr.To[int32](80)),
					},
				},
			},
			want: true,
		},
		{
			name: "Matching any listener (httpListener)",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
					},
				},
			},
			want: true,
		},
		{
			name: "Matching any listener (httpNoMatchListener)",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, parentRefMatched(gw, tt.args.listener, "default", tt.args.refs), "parentRefMatched(%v, %v, %v, %v)", gw, tt.args.listener, tt.args.routeNamespace, tt.args.refs)
		})
	}
}
