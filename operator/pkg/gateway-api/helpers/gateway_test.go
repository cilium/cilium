// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
)

func Test_hasMatchingController(t *testing.T) {
	logger := hivetest.Logger(t)
	c := fake.NewClientBuilder().WithScheme(TestScheme(AllOptionalKinds)).WithObjects(testhelpers.ControllerTestFixture...).Build()
	fn := GatewayHasMatchingControllerFn(t.Context(), c, "io.cilium/gateway-controller", logger)

	t.Run("invalid object", func(t *testing.T) {
		res := fn(&corev1.Pod{})
		require.False(t, res)
	})

	t.Run("gateway is matched by controller", func(t *testing.T) {
		res := fn(&gatewayv1.Gateway{
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "cilium",
			},
		})
		require.True(t, res)
	})

	t.Run("gateway is linked to non-existent class", func(t *testing.T) {
		res := fn(&gatewayv1.Gateway{
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "non-existent",
			},
		})
		require.False(t, res)
	})
}
