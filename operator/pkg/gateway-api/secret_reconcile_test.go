// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

var secretsNamespace = "cilium-secrets-test"

var secretFixture = []client.Object{
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: secretsNamespace,
			Name:      "test-synced-secret-no-source",
			Labels: map[string]string{
				owningSecretNamespace: "test",
				owningSecretName:      "synced-secret-no-source",
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
				owningSecretNamespace: "test",
				owningSecretName:      "syced-secret-no-reference",
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
				owningSecretNamespace: "test",
				owningSecretName:      "synced-secret-with-source-and-ref",
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
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1.GroupName,
		},
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
					Hostname: model.AddressOf[gatewayv1.Hostname]("*.cilium.io"),
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
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1.GroupName,
		},
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
					Hostname: model.AddressOf[gatewayv1.Hostname]("*.acme.io"),
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
}

func Test_SecretSync_Reconcile(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(secretFixture...).
		Build()
	r := &secretSyncer{
		client:                   c,
		logger:                   logrus.New(),
		mainObject:               &gatewayv1.Gateway{},
		mainObjectEnqueueFunc:    enqueueTLSSecrets(c),
		mainObjectReferencedFunc: isUsedByCiliumGateway,
		secretsNamespace:         secretsNamespace,
	}

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
		err = r.client.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-synced-secret-no-source"}, secret)

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
		err = r.client.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-synced-secret-no-reference"}, secret)

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
		err = r.client.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-synced-secret-with-source-and-ref"}, secret)
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
		err = r.client.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-synced-secret-non-cilium-ref"}, secret)

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
		err = r.client.Get(context.Background(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-secret-with-ref-not-synced"}, secret)
		require.NoError(t, err)
	})
}
