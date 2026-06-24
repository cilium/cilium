// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gateway_api "github.com/cilium/cilium/operator/pkg/gateway-api"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	syncnames "github.com/cilium/cilium/pkg/secretsync/names"
)

const testConfigMapSyncControllerName = "example.com/test-gateway-controller"

var configMapFixture = []client.Object{
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: secretsNamespace,
			Name:      "test-cfgmap-synced-configmap-no-source",
			Labels: map[string]string{
				secretsync.OwningConfigMapNamespace: "test",
				secretsync.OwningConfigMapName:      "synced-configmap-no-source",
			},
		},
	},
	&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "synced-configmap-no-reference",
		},
	},
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: secretsNamespace,
			Name:      "test-cfgmap-synced-configmap-no-reference",
			Labels: map[string]string{
				secretsync.OwningConfigMapNamespace: "test",
				secretsync.OwningConfigMapName:      "synced-configmap-no-reference",
			},
		},
	},
	&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "synced-configmap-with-source-and-ref",
		},
	},
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: secretsNamespace,
			Name:      "test-cfgmap-synced-configmap-with-source-and-ref",
			Labels: map[string]string{
				secretsync.OwningConfigMapNamespace: "test",
				secretsync.OwningConfigMapName:      "synced-configmap-with-source-and-ref",
			},
		},
	},
	&gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "valid-backendtlspolicy",
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(""),
						Kind:  gatewayv1.Kind("Service"),
						Name:  "backend-with-tls",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{
						Group: gatewayv1.Group(""),
						Kind:  gatewayv1.Kind("ConfigMap"),
						Name:  "synced-configmap-with-source-and-ref",
					},
				},
			},
		},
		// Status is necessary because we're only going to use this BackendTLSPolicy
		// if it's already validated by the Gateway API reconciler.
		Status: gatewayv1.PolicyStatus{
			Ancestors: []gatewayv1.PolicyAncestorStatus{
				{
					ControllerName: testConfigMapSyncControllerName,
					Conditions: []metav1.Condition{
						{
							Type:   "Accepted",
							Status: metav1.ConditionTrue,
						},
					},
				},
			},
		},
	},
	&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "configmap-with-other-ref-not-synced",
		},
	},
	&gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "other-controller-backendtlspolicy",
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(""),
						Kind:  gatewayv1.Kind("Service"),
						Name:  "backend-with-tls",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{
						Group: gatewayv1.Group(""),
						Kind:  gatewayv1.Kind("ConfigMap"),
						Name:  "configmap-with-other-ref-not-synced",
					},
				},
			},
		},
		// Status is necessary because we check it for validity.
		Status: gatewayv1.PolicyStatus{
			Ancestors: []gatewayv1.PolicyAncestorStatus{
				{
					ControllerName: "some.other/gateway-controller",
					Conditions: []metav1.Condition{
						{
							Type:   "Accepted",
							Status: metav1.ConditionTrue,
						},
					},
				},
			},
		},
	},
	&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "configmap-referenced-not-synced",
		},
	},
	&gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "create-secret-backendtlspolicy",
		},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
						Group: gatewayv1.Group(""),
						Kind:  gatewayv1.Kind("Service"),
						Name:  "backend-with-tls",
					},
				},
			},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				CACertificateRefs: []gatewayv1.LocalObjectReference{
					{
						Group: gatewayv1.Group(""),
						Kind:  gatewayv1.Kind("ConfigMap"),
						Name:  "configmap-referenced-not-synced",
					},
				},
			},
		},
		// Status is necessary because we check it for validity.
		Status: gatewayv1.PolicyStatus{
			Ancestors: []gatewayv1.PolicyAncestorStatus{
				{
					ControllerName: testConfigMapSyncControllerName,
					Conditions: []metav1.Condition{
						{
							Type:   "Accepted",
							Status: metav1.ConditionTrue,
						},
					},
				},
			},
		},
	},
}

func Test_ConfigMapSync_Reconcile(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(configMapFixture...).
		WithIndex(&gatewayv1.BackendTLSPolicy{}, indexers.BackendTLSPolicyConfigMapIndex, indexers.IndexBTLSPolicyByConfigMap).
		Build()

	gatewayHandler := gateway_api.NewSecretSyncHandler(c, logger, testConfigMapSyncControllerName)

	r := secretsync.NewConfigMapSyncReconciler(c, logger, []*secretsync.ConfigMapSyncRegistration{
		{
			RefObject:            &gatewayv1.Gateway{},
			RefObjectEnqueueFunc: gatewayHandler.EnqueueBackendTLSPolicyConfigMaps(),
			RefObjectCheckFunc:   gatewayHandler.ConfigMapIsReferencedInGateway,
			SecretsNamespace:     secretsNamespace,
		},
	},
		time.Minute,
		0.1,
	)

	t.Run("delete synced secret if source configmap doesn't exist", func(t *testing.T) {
		result, err := r.Reconcile(t.Context(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "synced-secret-no-source",
			},
		})
		require.NoError(t, err)
		// This one should not be requeued, as it doesn't exist any more.
		require.Equal(t, ctrl.Result{}, result)

		secret := &corev1.Secret{}
		err = c.Get(t.Context(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-synced-secret-no-source"}, secret)

		require.Error(t, err)
		require.ErrorContains(t, err, "secrets \"test-synced-secret-no-source\" not found")
	})

	t.Run("delete synced secret if source configmap isn't referenced by a Cilium BackendTLSPolicy resource", func(t *testing.T) {
		result, err := r.Reconcile(t.Context(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "synced-configmap-no-reference",
			},
		})
		require.NoError(t, err)
		// This one should not be requeued, as it is not referenced by a BackendTLSPolicy resource.
		require.Equal(t, ctrl.Result{}, result)

		secret := &corev1.Secret{}
		err = c.Get(t.Context(), types.NamespacedName{Namespace: secretsNamespace, Name: "test-cfgmap-synced-configmap-no-reference"}, secret)

		require.Error(t, err)
		require.ErrorContains(t, err, "secrets \"test-cfgmap-synced-configmap-no-reference\" not found")
	})

	t.Run("keep synced secret if source configmap exists and is referenced by a BackendTLSPolicy resource", func(t *testing.T) {
		result, err := r.Reconcile(t.Context(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "synced-configmap-with-source-and-ref",
			},
		})
		require.NoError(t, err)
		require.True(t, resultHasResync(result))

		secret := &corev1.Secret{}
		err = c.Get(t.Context(), syncedConfigMapSecretKey(secretsNamespace, "test", "synced-configmap-with-source-and-ref"), secret)
		require.NoError(t, err)
	})

	t.Run("don't create synced secret for source configmap that is referenced by a non Cilium BackendTLSPolicy resource", func(t *testing.T) {
		result, err := r.Reconcile(t.Context(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "configmap-with-other-ref-not-synced",
			},
		})
		require.NoError(t, err)
		// This one should not be requeued, as it is not referenced by a Cilium Gateway resource.
		require.Equal(t, ctrl.Result{}, result)

		secret := &corev1.Secret{}
		err = c.Get(t.Context(), syncedConfigMapSecretKey(secretsNamespace, "test", "configmap-with-other-ref-not-synced"), secret)

		require.True(t, k8sErrors.IsNotFound(err))
	})

	t.Run("create synced secret for source secret that is referenced by a Cilium Gateway resource", func(t *testing.T) {
		result, err := r.Reconcile(t.Context(), ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "test",
				Name:      "configmap-referenced-not-synced",
			},
		})
		require.NoError(t, err)
		require.True(t, resultHasResync(result))

		secret := &corev1.Secret{}
		err = c.Get(t.Context(), syncedConfigMapSecretKey(secretsNamespace, "test", "configmap-referenced-not-synced"), secret)
		require.NoError(t, err)
		requireSourceAnnotations(t, secret, secretsync.SourceKindConfigMap, "test", "configmap-referenced-not-synced")
	})
}

func Test_ConfigMapSync_Reconcile_SourceNameCollision(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	first := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "ca-prod"},
		Data:       map[string]string{"ca.crt": "first"},
	}
	second := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a-ca", Name: "prod"},
		Data:       map[string]string{"ca.crt": "second"},
	}

	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(first, second).
		Build()

	referenced := map[types.NamespacedName]struct{}{
		{Namespace: first.Namespace, Name: first.Name}:   {},
		{Namespace: second.Namespace, Name: second.Name}: {},
	}
	r := secretsync.NewConfigMapSyncReconciler(c, logger, []*secretsync.ConfigMapSyncRegistration{
		{
			RefObjectCheckFunc: func(_ context.Context, _ client.Client, _ *slog.Logger, obj *corev1.ConfigMap) bool {
				_, ok := referenced[types.NamespacedName{Namespace: obj.Namespace, Name: obj.Name}]
				return ok
			},
			SecretsNamespace: secretsNamespace,
		},
	}, time.Minute, 0.1)

	for _, source := range []*corev1.ConfigMap{first, second} {
		result, err := r.Reconcile(t.Context(), ctrl.Request{
			NamespacedName: types.NamespacedName{Namespace: source.Namespace, Name: source.Name},
		})
		require.NoError(t, err)
		require.True(t, resultHasResync(result))
	}

	firstSynced := &corev1.Secret{}
	err := c.Get(t.Context(), syncedConfigMapSecretKey(secretsNamespace, first.Namespace, first.Name), firstSynced)
	require.NoError(t, err)
	require.Equal(t, []byte("first"), firstSynced.Data["ca.crt"])
	requireSourceAnnotations(t, firstSynced, secretsync.SourceKindConfigMap, first.Namespace, first.Name)

	secondSynced := &corev1.Secret{}
	err = c.Get(t.Context(), syncedConfigMapSecretKey(secretsNamespace, second.Namespace, second.Name), secondSynced)
	require.NoError(t, err)
	require.Equal(t, []byte("second"), secondSynced.Data["ca.crt"])
	requireSourceAnnotations(t, secondSynced, secretsync.SourceKindConfigMap, second.Namespace, second.Name)
	require.NotEqual(t, firstSynced.Name, secondSynced.Name)
}

func syncedConfigMapSecretKey(secretsNamespace, sourceNamespace, sourceName string) types.NamespacedName {
	return types.NamespacedName{
		Namespace: secretsNamespace,
		Name: syncnames.SyncedConfigMapSecretName(types.NamespacedName{
			Namespace: sourceNamespace,
			Name:      sourceName,
		}),
	}
}
