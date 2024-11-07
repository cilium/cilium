// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync_test

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gateway_api "github.com/cilium/cilium/operator/pkg/gateway-api"
	"github.com/cilium/cilium/operator/pkg/ingress"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var secretsNamespace = "cilium-secrets-test"

var secretFixture = []client.Object{
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: secretsNamespace,
			Name:      "test-synced-secret-no-source",
			Labels: map[string]string{
				secretsync.OwningSecretNamespace: "test",
				secretsync.OwningSecretName:      "synced-secret-no-source",
			},
		},
	},
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "synced-secret-no-reference",
		},
	},
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: secretsNamespace,
			Name:      "test-synced-secret-no-reference",
			Labels: map[string]string{
				secretsync.OwningSecretNamespace: "test",
				secretsync.OwningSecretName:      "syced-secret-no-reference",
			},
		},
	},
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "synced-secret-with-source-and-ref",
		},
	},
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: secretsNamespace,
			Name:      "test-synced-secret-with-source-and-ref",
			Labels: map[string]string{
				secretsync.OwningSecretNamespace: "test",
				secretsync.OwningSecretName:      "synced-secret-with-source-and-ref",
			},
		},
	},
	&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "io.cilium/gateway-controller",
		},
	},
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "valid-gateway",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
					Protocol: "HTTPS",
					TLS: &gatewayv1.GatewayTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Name: "synced-secret-with-source-and-ref",
							},
							{
								Name: "secret-with-ref-not-synced",
							},
						},
					},
				},
			},
		},
	},
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "secret-with-ref-not-synced",
		},
	},
	&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "third-party",
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: "third-party",
		},
	},
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "valid-gateway-non-cilium",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "third-party",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Hostname: ptr.To[gatewayv1.Hostname]("*.acme.io"),
					Protocol: "HTTPS",
					TLS: &gatewayv1.GatewayTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Name: "secret-with-non-cilium-ref",
							},
						},
					},
				},
			},
		},
	},
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "secret-shared-not-synced",
		},
	},
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "valid-gateway-shared",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Port:     443,
					Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
					Protocol: "HTTPS",
					TLS: &gatewayv1.GatewayTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Name: "secret-shared-not-synced",
							},
						},
					},
				},
			},
		},
	},
	&networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "valid-ingress-cilium",
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("cilium"),
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"*.cilium.io"},
					SecretName: "secret-shared-not-synced",
				},
			},
		},
	},
}

func Test_SecretSync_Reconcile(t *testing.T) {
	logger := hivetest.Logger(t)

	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(secretFixture...).
		Build()

	r := secretsync.NewSecretSyncReconciler(c, logger, []*secretsync.SecretSyncRegistration{
		{
			RefObject:            &gatewayv1.Gateway{},
			RefObjectEnqueueFunc: gateway_api.EnqueueTLSSecrets(c, logger),
			RefObjectCheckFunc:   gateway_api.IsReferencedByCiliumGateway,
			SecretsNamespace:     secretsNamespace,
		},
		{
			RefObject:            &networkingv1.Ingress{},
			RefObjectEnqueueFunc: ingress.EnqueueReferencedTLSSecrets(c, logger),
			RefObjectCheckFunc:   ingress.IsReferencedByCiliumIngress,
			SecretsNamespace:     secretsNamespace + "-2",
		},
	})

	t.Run("delete synced secret if source secret doesn't exist", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "synced-secret-no-source",
			},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		secret := &corev1.Secret{}
		err = c.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-synced-secret-no-source"}, secret)

		require.Error(t, err)
		require.ErrorContains(t, err, "secrets \"test-synced-secret-no-source\" not found")
	})

	t.Run("delete synced secret if source secret isn't referenced by a CIlium Gateway resource", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "synced-secret-no-reference",
			},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		secret := &corev1.Secret{}
		err = c.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-synced-secret-no-reference"}, secret)

		require.Error(t, err)
		require.ErrorContains(t, err, "secrets \"test-synced-secret-no-reference\" not found")
	})

	t.Run("keep synced secret if source secret exists and is referenced by a Gateway resource", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "synced-secret-with-source-and-ref",
			},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		secret := &corev1.Secret{}
		err = c.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-synced-secret-with-source-and-ref"}, secret)
		require.NoError(t, err)
	})

	t.Run("don't create synced secret for source secret that is referenced by a non Cilium Gateway resource", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "secret-with-non-cilium-ref",
			},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		secret := &corev1.Secret{}
		err = c.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-synced-secret-non-cilium-ref"}, secret)

		require.Error(t, err)
		require.ErrorContains(t, err, "secrets \"test-synced-secret-non-cilium-ref\" not found")
	})

	t.Run("create synced secret for source secret that is referenced by a Cilium Gateway resource", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "secret-with-ref-not-synced",
			},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		secret := &corev1.Secret{}
		err = c.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-secret-with-ref-not-synced"}, secret)
		require.NoError(t, err)
	})

	t.Run("create synced secret in multiple namespaces for source secret that is referenced by a Gateway and Ingress", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "secret-shared-not-synced",
			},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		err = c.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-secret-shared-not-synced"}, &corev1.Secret{})
		require.NoError(t, err)

		err = c.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace + "-2", Name: "test-secret-shared-not-synced"}, &corev1.Secret{})
		require.NoError(t, err)
	})

	t.Run("delete synced secret in ingress namespace after deleting the Ingress resource", func(t *testing.T) {
		ingress := networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      "valid-ingress-cilium",
			},
		}

		var err error
		err = c.Delete(context.Background(), &ingress)
		require.NoError(t, err)

		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "secret-shared-not-synced",
			},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		err = c.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-secret-shared-not-synced"}, &corev1.Secret{})
		require.NoError(t, err)

		err = c.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace + "-2", Name: "test-secret-shared-not-synced"}, &corev1.Secret{})
		require.True(t, k8sErrors.IsNotFound(err))
	})
}

var secretFixtureDefaultSecret = []client.Object{
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "unsynced-secret-no-reference",
		},
	},
}

func Test_SecretSync_Reconcile_WithDefaultSecret(t *testing.T) {
	logger := hivetest.Logger(t)

	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(secretFixtureDefaultSecret...).
		Build()
	r := secretsync.NewSecretSyncReconciler(c, logger, []*secretsync.SecretSyncRegistration{
		{
			RefObject:            &gatewayv1.Gateway{},
			RefObjectEnqueueFunc: gateway_api.EnqueueTLSSecrets(c, logger),
			RefObjectCheckFunc:   gateway_api.IsReferencedByCiliumGateway,
			SecretsNamespace:     secretsNamespace,
			DefaultSecret: &secretsync.DefaultSecret{
				Namespace: "test",
				Name:      "unsynced-secret-no-reference",
			},
		},
	})

	t.Run("create synced secret for source secret that is the default secret and therefore doesn't need to be referenced by any Cilium Gateway resource", func(t *testing.T) {
		result, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "unsynced-secret-no-reference",
			},
		})
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, result)

		secret := &corev1.Secret{}
		err = c.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-unsynced-secret-no-reference"}, secret)
		require.NoError(t, err)
	})
}

func testScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ciliumv2.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.AddToScheme(scheme))

	return scheme
}
