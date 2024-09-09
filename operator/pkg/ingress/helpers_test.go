// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestIsIngressClassMarkedAsDefault(t *testing.T) {
	testCases := []struct {
		desc         string
		ingressClass networkingv1.IngressClass
		isDefault    bool
	}{
		{
			desc: "Is default IngressClass if annotation is present and set to true",
			ingressClass: networkingv1.IngressClass{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
					Annotations: map[string]string{
						"ingressclass.kubernetes.io/is-default-class": "true",
					},
				},
			},
			isDefault: true,
		},
		{
			desc: "Isn't default IngressClass if annotation is present and set to false",
			ingressClass: networkingv1.IngressClass{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
					Annotations: map[string]string{
						"ingressclass.kubernetes.io/is-default-class": "false",
					},
				},
			},
			isDefault: false,
		},
		{
			desc: "Isn't default IngressClass if annotation isn't present",
			ingressClass: networkingv1.IngressClass{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "test",
					Name:        "test",
					Annotations: map[string]string{},
				},
			},
			isDefault: false,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			isDefault, err := isIngressClassMarkedAsDefault(tC.ingressClass)
			require.NoError(t, err)
			require.Equal(t, tC.isDefault, isDefault)
		})
	}
}

func TestIsCiliumManagedIngress(t *testing.T) {
	fakeLogger := hivetest.Logger(t)

	testCases := []struct {
		desc    string
		ingress networkingv1.Ingress
		fixture []client.Object
		managed bool
	}{
		{
			desc: "Marked via IngressClassName",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr.To("cilium"),
				},
			},
			fixture: []client.Object{},
			managed: true,
		},
		{
			desc: "Marked via annotation",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
					Annotations: map[string]string{
						"kubernetes.io/ingress.class": "cilium",
					},
				},
				Spec: networkingv1.IngressSpec{},
			},
			fixture: []client.Object{},
			managed: true,
		},
		{
			desc: "Legacy ingress class annotation takes presedence over ingressClassName field",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
					Annotations: map[string]string{
						"kubernetes.io/ingress.class": "other",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr.To("cilium"),
				},
			},
			fixture: []client.Object{},
			managed: false,
		},
		{
			desc: "Cilium is default IngressClass and Ingress has no specific class set",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				},
				Spec: networkingv1.IngressSpec{},
			},
			fixture: []client.Object{
				&networkingv1.IngressClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cilium",
						Annotations: map[string]string{
							"ingressclass.kubernetes.io/is-default-class": "true",
						},
					},
				},
			},
			managed: true,
		},
		{
			desc: "Cilium isn't IngressClass (annotation set to false) and Ingress has no specific class set",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				},
				Spec: networkingv1.IngressSpec{},
			},
			fixture: []client.Object{
				&networkingv1.IngressClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cilium",
						Annotations: map[string]string{
							"ingressclass.kubernetes.io/is-default-class": "false",
						},
					},
				},
			},
			managed: false,
		},
		{
			desc: "Cilium isn't IngressClass (annotation missconfigured) and Ingress has no specific class set",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				},
				Spec: networkingv1.IngressSpec{},
			},
			fixture: []client.Object{
				&networkingv1.IngressClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cilium",
						Annotations: map[string]string{
							"ingressclass.kubernetes.io/is-default-class": "wrong-bool",
						},
					},
				},
			},
			managed: false,
		},
		{
			desc: "Cilium isn't IngressClass (annotation not present) and Ingress has no specific class set",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				},
				Spec: networkingv1.IngressSpec{},
			},
			fixture: []client.Object{
				&networkingv1.IngressClass{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "cilium",
						Annotations: map[string]string{},
					},
				},
			},
			managed: false,
		},
		{
			desc: "Cilium is default IngressClass but  Ingress has set another specific Ingress class",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr.To("other"),
				},
			},
			fixture: []client.Object{
				&networkingv1.IngressClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cilium",
						Annotations: map[string]string{
							"ingressclass.kubernetes.io/is-default-class": "true",
						},
					},
				},
			},
			managed: false,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(testScheme()).
				WithObjects(tC.fixture...).
				Build()

			isManaged := isCiliumManagedIngress(context.Background(), fakeClient, fakeLogger, tC.ingress)
			require.Equal(t, tC.managed, isManaged)
		})
	}
}

func testScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ciliumv2.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.AddToScheme(scheme))

	return scheme
}
