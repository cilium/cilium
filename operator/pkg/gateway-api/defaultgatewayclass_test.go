// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestCreateDefaultGatewayClass(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, gatewayv1.Install(scheme))
	key := types.NamespacedName{Name: defaultGatewayClassName}

	t.Run("created with Helm ownership metadata", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		require.NoError(t, createDefaultGatewayClass(t.Context(), hivetest.Logger(t), c, "kube-system/cilium"))

		gwc := &gatewayv1.GatewayClass{}
		require.NoError(t, c.Get(t.Context(), key, gwc))
		require.Equal(t, gatewayv1.GatewayController(defaultControllerName), gwc.Spec.ControllerName)
		require.Equal(t, ptr.To(defaultGatewayClassDescription), gwc.Spec.Description)
		require.Equal(t, "Helm", gwc.Labels["app.kubernetes.io/managed-by"])
		require.Equal(t, "cilium", gwc.Annotations["meta.helm.sh/release-name"])
		require.Equal(t, "kube-system", gwc.Annotations["meta.helm.sh/release-namespace"])

		// Idempotent.
		require.NoError(t, createDefaultGatewayClass(t.Context(), hivetest.Logger(t), c, "kube-system/cilium"))
	})

	t.Run("created without Helm release", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		require.NoError(t, createDefaultGatewayClass(t.Context(), hivetest.Logger(t), c, ""))

		gwc := &gatewayv1.GatewayClass{}
		require.NoError(t, c.Get(t.Context(), key, gwc))
		require.Empty(t, gwc.Labels)
		require.Empty(t, gwc.Annotations)
	})

	t.Run("existing GatewayClass is not modified", func(t *testing.T) {
		existing := &gatewayv1.GatewayClass{
			ObjectMeta: metav1.ObjectMeta{Name: defaultGatewayClassName, Labels: map[string]string{"owner": "user"}},
			Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.com/other"},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
		require.NoError(t, createDefaultGatewayClass(t.Context(), hivetest.Logger(t), c, "kube-system/cilium"))

		gwc := &gatewayv1.GatewayClass{}
		require.NoError(t, c.Get(t.Context(), key, gwc))
		require.Equal(t, existing.Spec, gwc.Spec)
		require.Equal(t, existing.Labels, gwc.Labels)
		require.Empty(t, gwc.Annotations)
	})

	t.Run("invalid Helm release", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		for _, release := range []string{"cilium", "/cilium", "kube-system/"} {
			require.Error(t, createDefaultGatewayClass(t.Context(), hivetest.Logger(t), c, release), release)
		}
	})
}
