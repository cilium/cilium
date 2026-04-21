// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
)

func Test_getGatewaysForSecret(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(TestScheme(AllOptionalKinds)).WithObjects(testhelpers.ControllerTestFixture...).Build()
	logger := hivetest.Logger(t)

	t.Run("secret is used in gateway", func(t *testing.T) {
		gwList := GetGatewaysForSecret(t.Context(), c, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret",
				Namespace: "default",
			},
		}, logger)

		require.Len(t, gwList, 1)
		require.Equal(t, "valid-gateway", gwList[0].Name)
	})

	t.Run("secret is not used in gateway", func(t *testing.T) {
		gwList := GetGatewaysForSecret(t.Context(), c, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret-not-used",
				Namespace: "default",
			},
		}, logger)

		require.Empty(t, gwList)
	})
}
