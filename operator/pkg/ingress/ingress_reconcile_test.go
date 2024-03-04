// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8sApiErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ingressTranslation "github.com/cilium/cilium/operator/pkg/model/translation/ingress"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	testCiliumNamespace                 = "cilium"
	testUseProxyProtocol                = true
	testCiliumSecretsNamespace          = "cilium-secrets"
	testDefaultLoadbalancingServiceName = "cilium-ingress"
	testDefaultSecretNamespace          = ""
	testDefaultSecretName               = ""
	testDefaultTimeout                  = 60
)

func TestReconcile(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	t.Run("Reconcile of Cilium Ingress without explicit loadbalancing mode will create the resources for the default loadbalancing mode if they don't exist", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		svc := corev1.Service{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &svc)
		require.NoError(t, err, "Dedicated loadbalancer service should exist")

		ep := corev1.Endpoints{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &ep)
		require.NoError(t, err, "Dedicated loadbalancer service endpoints should exist")

		cec := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test-test"}, &cec)
		require.NoError(t, err, "Dedicated CiliumEnvoyConfig should exist")

		sharedCEC := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: testCiliumNamespace, Name: testDefaultLoadbalancingServiceName}, &sharedCEC)
		require.NoError(t, err, "Attempt to cleanup shared CiliumEnvoyConfig will create an empty one")
		require.Empty(t, sharedCEC.Spec.Resources)
	})

	t.Run("Reconcile of Ingress without specific IngressClassName will create resources if cilium IngressClass is the default", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
					},
					Spec: networkingv1.IngressSpec{
						DefaultBackend: defaultBackend(),
					},
				},
				&networkingv1.IngressClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cilium",
						Annotations: map[string]string{
							"ingressclass.kubernetes.io/is-default-class": "true",
						},
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		svc := corev1.Service{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &svc)
		require.NoError(t, err, "Dedicated loadbalancer service should exist")

		ep := corev1.Endpoints{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &ep)
		require.NoError(t, err, "Dedicated loadbalancer service endpoints should exist")

		cec := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test-test"}, &cec)
		require.NoError(t, err, "Dedicated CiliumEnvoyConfig should exist")

		sharedCEC := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: testCiliumNamespace, Name: testDefaultLoadbalancingServiceName}, &sharedCEC)
		require.NoError(t, err, "Attempt to cleanup shared CiliumEnvoyConfig will create an empty one")
		require.Empty(t, sharedCEC.Spec.Resources)
	})

	t.Run("Reconcile of Ingress without specific IngressClassName won't create resources if cilium IngressClass is not the default", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
					},
					Spec: networkingv1.IngressSpec{
						DefaultBackend: defaultBackend(),
					},
				},
				&networkingv1.IngressClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cilium",
						Annotations: map[string]string{
							"ingressclass.kubernetes.io/is-default-class": "false",
						},
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &corev1.Service{})
		require.True(t, k8sApiErrors.IsNotFound(err), "Service should not be created")

		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &corev1.Endpoints{})
		require.True(t, k8sApiErrors.IsNotFound(err), "Endpoints should not be created")

		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test-test"}, &ciliumv2.CiliumEnvoyConfig{})
		require.True(t, k8sApiErrors.IsNotFound(err), "CiliumEnvoyConfig should not be created")
	})

	t.Run("Reconcile of shared Cilium Ingress will create the shared CiliumEnvoyConfig in the cilium namespace", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
						Annotations: map[string]string{
							"ingress.cilium.io/loadbalancer-mode": "shared",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		sharedCEC := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: testCiliumNamespace, Name: testDefaultLoadbalancingServiceName}, &sharedCEC)
		require.NoError(t, err, "Shared CiliumEnvoyConfig should exist for shared Ingress")
		require.NotEmpty(t, sharedCEC.Spec.Resources)

		svc := corev1.Service{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &svc)
		require.True(t, k8sApiErrors.IsNotFound(err), "Dedicated loadbalancer service should not exist for shared Ingress")

		ep := corev1.Endpoints{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &ep)
		require.True(t, k8sApiErrors.IsNotFound(err), "Dedicated loadbalancer endpoints should not exist for shared Ingress")

		cec := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test-test"}, &cec)
		require.True(t, k8sApiErrors.IsNotFound(err), "Dedicated CiliumEnvoyConfig should not exist for shared Ingress")
	})

	t.Run("Reconcile of Cilium Ingress will cleanup any potentially existing resources of the other loadbalancing mode (changing from dedicated -> shared)", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
						Annotations: map[string]string{
							"ingress.cilium.io/loadbalancer-mode": "shared",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "cilium-ingress-test",
					},
				},
				&corev1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "cilium-ingress-test",
					},
				},
				&ciliumv2.CiliumEnvoyConfig{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "cilium-ingress-test-test",
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		sharedCEC := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: testCiliumNamespace, Name: testDefaultLoadbalancingServiceName}, &sharedCEC)
		require.NoError(t, err, "Shared CiliumEnvoyConfig should exist for shared Ingress")
		require.NotEmpty(t, sharedCEC.Spec.Resources)

		svc := corev1.Service{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &svc)
		require.True(t, k8sApiErrors.IsNotFound(err), "Dedicated loadbalancer service should not exist for shared Ingress")

		ep := corev1.Endpoints{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &ep)
		require.True(t, k8sApiErrors.IsNotFound(err), "Dedicated loadbalancer endpoints should not exist for shared Ingress")

		cec := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test-test"}, &cec)
		require.True(t, k8sApiErrors.IsNotFound(err), "Dedicated CiliumEnvoyConfig should not exist for shared Ingress")
	})

	t.Run("Reconcile of Cilium Ingress will cleanup any potentially existing resources of the other loadbalancing mode (changing from shared -> dedicated)", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
						Annotations: map[string]string{
							"ingress.cilium.io/loadbalancer-mode": "dedicated",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
				&ciliumv2.CiliumEnvoyConfig{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testCiliumNamespace,
						Name:      testDefaultLoadbalancingServiceName,
					},
					Spec: ciliumv2.CiliumEnvoyConfigSpec{
						Resources: []ciliumv2.XDSResource{
							{
								Any: &anypb.Any{
									TypeUrl: envoy.ListenerTypeURL,
								},
							},
						},
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		svc := corev1.Service{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &svc)
		require.NoError(t, err, "Dedicated loadbalancer service should exist")

		ep := corev1.Endpoints{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &ep)
		require.NoError(t, err, "Dedicated loadbalancer service endpoints should exist")

		cec := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test-test"}, &cec)
		require.NoError(t, err, "Dedicated CiliumEnvoyConfig should exist")

		sharedCEC := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: testCiliumNamespace, Name: testDefaultLoadbalancingServiceName}, &sharedCEC)
		require.NoError(t, err, "Attempt to cleanup shared CiliumEnvoyConfig will replace it with an empty one")
		require.Empty(t, sharedCEC.Spec.Resources)
	})

	t.Run("Reconcile of a non-existent, potentially deleted, Cilium Ingress will try to cleanup any potentially existing shared resources", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&ciliumv2.CiliumEnvoyConfig{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testCiliumNamespace,
						Name:      testDefaultLoadbalancingServiceName,
					},
					Spec: ciliumv2.CiliumEnvoyConfigSpec{
						Resources: []ciliumv2.XDSResource{
							{
								Any: &anypb.Any{
									TypeUrl: envoy.ListenerTypeURL,
								},
							},
						},
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		sharedCEC := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: testCiliumNamespace, Name: testDefaultLoadbalancingServiceName}, &sharedCEC)
		require.NoError(t, err, "Attempt to cleanup shared CiliumEnvoyConfig will replace it with an empty one")
		require.Empty(t, sharedCEC.Spec.Resources)
	})

	t.Run("Reconcile of non Cilium Ingress will cleanup any potentially existing resources (dedicated and shared) and reset the Ingress status", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
						Annotations: map[string]string{
							"ingress.cilium.io/loadbalancer-mode": "dedicated",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("other"),
						DefaultBackend:   defaultBackend(),
					},
					Status: networkingv1.IngressStatus{
						LoadBalancer: networkingv1.IngressLoadBalancerStatus{
							Ingress: []networkingv1.IngressLoadBalancerIngress{
								{
									IP: "172.21.255.202",
								},
							},
						},
					},
				},
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "cilium-ingress-test",
					},
				},
				&corev1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "cilium-ingress-test",
					},
				},
				&ciliumv2.CiliumEnvoyConfig{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "cilium-ingress-test-test",
					},
				},
				&ciliumv2.CiliumEnvoyConfig{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testCiliumNamespace,
						Name:      testDefaultLoadbalancingServiceName,
					},
					Spec: ciliumv2.CiliumEnvoyConfigSpec{
						Resources: []ciliumv2.XDSResource{
							{
								Any: &anypb.Any{
									TypeUrl: envoy.ListenerTypeURL,
								},
							},
						},
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		svc := corev1.Service{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &svc)
		require.True(t, k8sApiErrors.IsNotFound(err), "Dedicated loadbalancer service should be cleaned up")

		ep := corev1.Endpoints{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &ep)
		require.True(t, k8sApiErrors.IsNotFound(err), "Dedicated loadbalancer endpoints should be cleaned up")

		cec := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test-test"}, &cec)
		require.True(t, k8sApiErrors.IsNotFound(err), "Dedicated CiliumEnvoyConfig should be cleaned up")

		sharedCEC := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: testCiliumNamespace, Name: testDefaultLoadbalancingServiceName}, &sharedCEC)
		require.NoError(t, err, "Attempt to cleanup shared CiliumEnvoyConfig will replace it with an empty one")
		require.Empty(t, sharedCEC.Spec.Resources)

		ingress := networkingv1.Ingress{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "test"}, &ingress)
		require.NoError(t, err)
		require.Empty(t, ingress.Status.LoadBalancer.Ingress, "Loadbalancer status of Ingress should be reset")
	})

	t.Run("Reconcile of dedicated Cilium Ingress will update the status according to the IP of the dedicated loadbalancer service", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
						Annotations: map[string]string{
							"ingress.cilium.io/loadbalancer-mode": "dedicated",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "cilium-ingress-test",
					},
					Status: corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{
								{
									IP: "172.21.255.202",
								},
							},
						},
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		ingress := networkingv1.Ingress{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "test"}, &ingress)
		require.NoError(t, err)
		require.Len(t, ingress.Status.LoadBalancer.Ingress, 1, "Loadbalancer status should contain the IP of the dedicated loadbalancer service")
		require.Equal(t, "172.21.255.202", ingress.Status.LoadBalancer.Ingress[0].IP, "Loadbalancer status should contain the IP of the dedicated loadbalancer service")
	})

	t.Run("Reconcile of shared Cilium Ingress will update the status according to the IP of the shared loadbalancer service", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
						Annotations: map[string]string{
							"ingress.cilium.io/loadbalancer-mode": "shared",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testCiliumNamespace,
						Name:      "cilium-ingress",
					},
					Status: corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{
								{
									IP: "172.21.255.200",
								},
							},
						},
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		ingress := networkingv1.Ingress{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "test"}, &ingress)
		require.NoError(t, err)
		require.Len(t, ingress.Status.LoadBalancer.Ingress, 1, "Loadbalancer status should contain the IP of the shared loadbalancer service")
		require.Equal(t, "172.21.255.200", ingress.Status.LoadBalancer.Ingress[0].IP, "Loadbalancer status should contain the IP of the shared loadbalancer service")
	})

	t.Run("Errors during the model translation are reported via error and result in re-enqueuing the reconcile request", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
						Annotations: map[string]string{
							"ingress.cilium.io/loadbalancer-mode": "dedicated",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.ErrorContains(t, err, "model source can't be empty")
		require.NotNil(t, result)
	})

	t.Run("Annotations and labels from the Ingress resource should be propagated to the Service if they match the configured prefixes", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
						Annotations: map[string]string{
							"ingress.cilium.io/loadbalancer-mode": "dedicated",
							"test.acme.io/test-annotation":        "test",
							"other.acme.io/test":                  "test",
						},
						Labels: map[string]string{
							"test.acme.io/test-label": "test",
							"other.acme.io/test":      "test",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{"test.acme.io/"}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		svc := corev1.Service{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &svc)
		require.NoError(t, err)

		require.Equal(t, map[string]string{"cilium.io/ingress": "true", "test.acme.io/test-label": "test"}, svc.Labels)
		require.Equal(t, map[string]string{"test.acme.io/test-annotation": "test"}, svc.Annotations)
	})

	t.Run("Additional existing annotations and labels on the Service, Endpoints & CEC should be preserved", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
						Annotations: map[string]string{
							"ingress.cilium.io/loadbalancer-mode": "dedicated",
							"test.acme.io/test-annotation":        "test",
							"other.acme.io/test-annotation":       "test",
						},
						Labels: map[string]string{
							"test.acme.io/test-label":  "test",
							"other.acme.io/test-label": "test",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "cilium-ingress-test",
						Annotations: map[string]string{
							"additional.annotation/test-annotation": "test",
						},
						Labels: map[string]string{
							"cilium.io/ingress":           "false",
							"additional.label/test-label": "test",
						},
					},
				},
				&corev1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "cilium-ingress-test",
						Annotations: map[string]string{
							"additional.annotation/test-annotation": "test",
						},
						Labels: map[string]string{
							"additional.label/test-label": "test",
						},
					},
				},
				&ciliumv2.CiliumEnvoyConfig{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "cilium-ingress-test-test",
						Annotations: map[string]string{
							"additional.annotation/test-annotation": "test",
						},
						Labels: map[string]string{
							"additional.label/test-label": "test",
						},
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		svc := corev1.Service{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &svc)
		require.NoError(t, err)

		require.Contains(t, svc.Labels, "cilium.io/ingress", "Existing labels should be overwritten if they have the same key")
		require.Equal(t, "true", svc.Labels["cilium.io/ingress"], "Existing label should be overwritten if they have the same key")

		require.Contains(t, svc.Labels, "additional.label/test-label", "Existing labels should not be deleted")
		require.Contains(t, svc.Annotations, "additional.annotation/test-annotation", "Existing annotations should not be deleted")

		ep := corev1.Endpoints{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &ep)
		require.NoError(t, err)

		require.Contains(t, ep.Labels, "additional.label/test-label", "Existing labels should not be deleted")
		require.Contains(t, ep.Annotations, "additional.annotation/test-annotation", "Existing annotations should not be deleted")

		cec := ciliumv2.CiliumEnvoyConfig{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test-test"}, &cec)
		require.NoError(t, err)

		require.Contains(t, cec.Labels, "additional.label/test-label", "Existing labels should not be deleted")
		require.Contains(t, cec.Annotations, "additional.annotation/test-annotation", "Existing annotations should not be deleted")
	})

	t.Run("Existing loadBalancerClass on Service should not be overwritten (e.g. scenarios where this gets set by a mutating webhook)", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "cilium-ingress-test",
					},
					Spec: corev1.ServiceSpec{
						LoadBalancerClass: model.AddressOf("service.k8s.aws/nlb"),
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		svc := corev1.Service{}
		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &svc)
		require.NoError(t, err)

		require.Equal(t, model.AddressOf("service.k8s.aws/nlb"), svc.Spec.LoadBalancerClass, "LoadbalancerClass should be preserved during reconciliation")
	})

	t.Run("If the deletionTimestamp is set (foreground deletion), no dependent objects should be modified or created", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:         "test",
						Name:              "test",
						DeletionTimestamp: model.AddressOf(metav1.Now()),
						Finalizers: []string{
							"foregroundDeletion",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
			).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &corev1.Service{})
		require.True(t, k8sApiErrors.IsNotFound(err), "Service should not be created")

		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &corev1.Endpoints{})
		require.True(t, k8sApiErrors.IsNotFound(err), "Endpoints should not be created")

		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test-test"}, &ciliumv2.CiliumEnvoyConfig{})
		require.True(t, k8sApiErrors.IsNotFound(err), "CiliumEnvoyConfig should not be created")
	})

	t.Run("If create operations fail due to namespace termination, no error should be reported", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
			).
			WithInterceptorFuncs(interceptor.Funcs{
				Create: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					return &k8sApiErrors.StatusError{
						ErrStatus: metav1.Status{
							Message: "unable to create new content in namespace test because it is being terminated",
							Reason:  metav1.StatusReasonForbidden,
							Details: &metav1.StatusDetails{
								Causes: []metav1.StatusCause{
									{
										Type: corev1.NamespaceTerminatingCause,
									},
								},
							},
						},
					}
				},
			}).
			Build()

		cecTranslator := translation.NewCECTranslator(testCiliumSecretsNamespace, testUseProxyProtocol, false, testDefaultTimeout, false, nil, false, false, 0)
		dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, false)

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, false, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &corev1.Service{})
		require.True(t, k8sApiErrors.IsNotFound(err), "Service should not be created")

		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test"}, &corev1.Endpoints{})
		require.True(t, k8sApiErrors.IsNotFound(err), "Endpoints should not be created")

		err = fakeClient.Get(context.Background(), types.NamespacedName{Namespace: "test", Name: "cilium-ingress-test-test"}, &ciliumv2.CiliumEnvoyConfig{})
		require.True(t, k8sApiErrors.IsNotFound(err), "CiliumEnvoyConfig should not be created")
	})
	t.Run("Reconcile of shared Cilium Ingress with external LB support will pass the configured port via model to the CEC Translator", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
						Annotations: map[string]string{
							"ingress.cilium.io/loadbalancer-mode": "shared",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
			).
			Build()

		cecTranslator := &fakeCECTranslator{}

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, nil, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, true, 55555, 55556)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Empty(t, cecTranslator.model.TLS)
		assert.Len(t, cecTranslator.model.HTTP, 1)
		assert.Equal(t, uint32(55555), cecTranslator.model.HTTP[0].Port)
	})

	t.Run("Reconcile of dedicated Cilium Ingress with external LB support will pass the annotated port to the CEC Translator", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithObjects(
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test",
						Name:      "test",
						Annotations: map[string]string{
							"ingress.cilium.io/loadbalancer-mode": "dedicated",
							"ingress.cilium.io/http-host-port":    "55555",
						},
					},
					Spec: networkingv1.IngressSpec{
						IngressClassName: model.AddressOf("cilium"),
						DefaultBackend:   defaultBackend(),
					},
				},
			).
			Build()

		cecTranslator := &fakeCECTranslator{}
		dedicatedIngressTranslator := &fakeDedicatedIngressTranslator{}

		reconciler := newIngressReconciler(logger, fakeClient, cecTranslator, dedicatedIngressTranslator, testCiliumNamespace, []string{}, testDefaultLoadbalancingServiceName, "dedicated", testDefaultSecretNamespace, testDefaultSecretName, false, true, 0, 0)

		result, err := reconciler.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Empty(t, dedicatedIngressTranslator.model.TLS)
		assert.Len(t, dedicatedIngressTranslator.model.HTTP, 1)
		assert.Equal(t, uint32(55555), dedicatedIngressTranslator.model.HTTP[0].Port)
	})
}

var _ translation.CECTranslator = &fakeCECTranslator{}

type fakeCECTranslator struct {
	model *model.Model
}

func (r *fakeCECTranslator) Translate(namespace string, name string, model *model.Model) (*ciliumv2.CiliumEnvoyConfig, error) {
	r.model = model

	return &ciliumv2.CiliumEnvoyConfig{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test"}}, nil
}

var _ translation.Translator = &fakeDedicatedIngressTranslator{}

type fakeDedicatedIngressTranslator struct {
	model *model.Model
}

func (r *fakeDedicatedIngressTranslator) Translate(model *model.Model) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error) {
	r.model = model

	return &ciliumv2.CiliumEnvoyConfig{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test"}},
		&corev1.Endpoints{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "test"}},
		nil
}

func defaultBackend() *networkingv1.IngressBackend {
	return &networkingv1.IngressBackend{
		Service: &networkingv1.IngressServiceBackend{
			Name: "test",
			Port: networkingv1.ServiceBackendPort{
				Number: 8080,
			},
		},
	}
}

func TestGetSharedListenerPorts(t *testing.T) {
	testCases := []struct {
		desc                                string
		hostNetworkEnabled                  bool
		hostNetworkSharedHTTPPort           uint32
		hostNetworkSharedTLSPassthroughPort uint32
		expectedPassthroughPort             uint32
		expectedInsecureHTTPPort            uint32
		expectedSecureHTTPPort              uint32
	}{
		{
			desc:                     "no external loadbalancer",
			hostNetworkEnabled:       false,
			expectedPassthroughPort:  443,
			expectedInsecureHTTPPort: 80,
			expectedSecureHTTPPort:   443,
		},
		{
			desc:                                "external loadbalancer with TLS & HTTP port 0",
			hostNetworkEnabled:                  true,
			hostNetworkSharedTLSPassthroughPort: 0,
			hostNetworkSharedHTTPPort:           0,
			expectedPassthroughPort:             443,
			expectedInsecureHTTPPort:            80,
			expectedSecureHTTPPort:              443,
		},
		{
			desc:                                "external loadbalancer with TLS port 0",
			hostNetworkEnabled:                  true,
			hostNetworkSharedTLSPassthroughPort: 0,
			hostNetworkSharedHTTPPort:           55555,
			expectedPassthroughPort:             443,
			expectedInsecureHTTPPort:            55555,
			expectedSecureHTTPPort:              55555,
		},
		{
			desc:                                "external loadbalancer with HTTP port 0",
			hostNetworkEnabled:                  true,
			hostNetworkSharedTLSPassthroughPort: 55555,
			hostNetworkSharedHTTPPort:           0,
			expectedPassthroughPort:             55555,
			expectedInsecureHTTPPort:            80,
			expectedSecureHTTPPort:              443,
		},
		{
			desc:                                "external loadbalancer with HTTP and TLS port set",
			hostNetworkEnabled:                  true,
			hostNetworkSharedTLSPassthroughPort: 55555,
			hostNetworkSharedHTTPPort:           55556,
			expectedPassthroughPort:             55555,
			expectedInsecureHTTPPort:            55556,
			expectedSecureHTTPPort:              55556,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			ir := ingressReconciler{
				hostNetworkEnabled:                  tC.hostNetworkEnabled,
				hostNetworkSharedHTTPPort:           tC.hostNetworkSharedHTTPPort,
				hostNetworkSharedTLSPassthroughPort: tC.hostNetworkSharedTLSPassthroughPort,
			}

			passthrough, insecureHTTP, secureHTTP := ir.getSharedListenerPorts()

			assert.Equal(t, tC.expectedPassthroughPort, passthrough)
			assert.Equal(t, tC.expectedInsecureHTTPPort, insecureHTTP)
			assert.Equal(t, tC.expectedSecureHTTPPort, secureHTTP)
		})
	}
}

func TestGetDedicatedListenerPorts(t *testing.T) {
	testCases := []struct {
		desc                     string
		hostNetworkEnabled       bool
		ingressAnnotations       map[string]string
		expectedPassthroughPort  uint32
		expectedInsecureHTTPPort uint32
		expectedSecureHTTPPort   uint32
	}{
		{
			desc:                     "no hostnetwork mode",
			hostNetworkEnabled:       false,
			expectedPassthroughPort:  443,
			expectedInsecureHTTPPort: 80,
			expectedSecureHTTPPort:   443,
		},
		{
			desc:               "hostnetwork without TLS annotation",
			hostNetworkEnabled: true,
			ingressAnnotations: map[string]string{
				"ingress.cilium.io/tls-passthrough-host-port": "55555",
			},
			expectedPassthroughPort:  55555,
			expectedInsecureHTTPPort: 80,
			expectedSecureHTTPPort:   443,
		},
		{
			desc:               "hostnetwork without HTTP annotation",
			hostNetworkEnabled: true,
			ingressAnnotations: map[string]string{
				"ingress.cilium.io/http-host-port": "55555",
			},
			expectedPassthroughPort:  443,
			expectedInsecureHTTPPort: 55555,
			expectedSecureHTTPPort:   55555,
		},
		{
			desc:               "hostnetwork with TLS & HTTP port 0",
			hostNetworkEnabled: true,
			ingressAnnotations: map[string]string{
				"ingress.cilium.io/tls-passthrough-host-port": "0",
				"ingress.cilium.io/http-host-port":            "0",
			},
			expectedPassthroughPort:  443,
			expectedInsecureHTTPPort: 80,
			expectedSecureHTTPPort:   443,
		},
		{
			desc:               "hostnetwork with TLS port 0",
			hostNetworkEnabled: true,
			ingressAnnotations: map[string]string{
				"ingress.cilium.io/tls-passthrough-host-port": "0",
				"ingress.cilium.io/http-host-port":            "55555",
			},
			expectedPassthroughPort:  443,
			expectedInsecureHTTPPort: 55555,
			expectedSecureHTTPPort:   55555,
		},
		{
			desc:               "hostnetwork with HTTP port 0",
			hostNetworkEnabled: true,
			ingressAnnotations: map[string]string{
				"ingress.cilium.io/tls-passthrough-host-port": "55555",
				"ingress.cilium.io/http-host-port":            "0",
			},
			expectedPassthroughPort:  55555,
			expectedInsecureHTTPPort: 80,
			expectedSecureHTTPPort:   443,
		},
		{
			desc:               "hostnetwork with invalid TLS value",
			hostNetworkEnabled: true,
			ingressAnnotations: map[string]string{
				"ingress.cilium.io/tls-passthrough-host-port": "invalid",
				"ingress.cilium.io/http-host-port":            "55555",
			},
			expectedPassthroughPort:  443,
			expectedInsecureHTTPPort: 55555,
			expectedSecureHTTPPort:   55555,
		},
		{
			desc:               "hostnetwork with invalid HTTP value",
			hostNetworkEnabled: true,
			ingressAnnotations: map[string]string{
				"ingress.cilium.io/tls-passthrough-host-port": "55555",
				"ingress.cilium.io/http-host-port":            "invalid",
			},
			expectedPassthroughPort:  55555,
			expectedInsecureHTTPPort: 80,
			expectedSecureHTTPPort:   443,
		},
		{
			desc:               "hostnetwork with HTTP and TLS port set",
			hostNetworkEnabled: true,
			ingressAnnotations: map[string]string{
				"ingress.cilium.io/tls-passthrough-host-port": "55555",
				"ingress.cilium.io/http-host-port":            "55556",
			},
			expectedPassthroughPort:  55555,
			expectedInsecureHTTPPort: 55556,
			expectedSecureHTTPPort:   55556,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			ir := ingressReconciler{
				logger:             logger,
				hostNetworkEnabled: tC.hostNetworkEnabled,
			}

			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: tC.ingressAnnotations,
				},
			}
			passthrough, insecureHTTP, secureHTTP := ir.getDedicatedListenerPorts(ingress)

			assert.Equal(t, tC.expectedPassthroughPort, passthrough)
			assert.Equal(t, tC.expectedInsecureHTTPPort, insecureHTTP)
			assert.Equal(t, tC.expectedSecureHTTPPort, secureHTTP)
		})
	}
}
