// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
)

func TestSNIHostnamesIntersect(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "same exact hostname",
			a:    "api.example.test",
			b:    "api.example.test",
			want: true,
		},
		{
			name: "different exact hostnames",
			a:    "api.example.test",
			b:    "web.example.test",
			want: false,
		},
		{
			name: "global wildcard intersects exact hostname",
			a:    "*",
			b:    "api.example.test",
			want: true,
		},
		{
			name: "empty hostname is catch-all",
			a:    "",
			b:    "api.example.test",
			want: true,
		},
		{
			name: "wildcard intersects matching exact hostname",
			a:    "*.example.test",
			b:    "api.example.test",
			want: true,
		},
		{
			name: "wildcard does not match bare suffix",
			a:    "*.example.test",
			b:    "example.test",
			want: false,
		},
		{
			name: "wildcards with shared suffix intersect",
			a:    "*.example.test",
			b:    "*.test",
			want: true,
		},
		{
			name: "wildcards with disjoint suffixes do not intersect",
			a:    "*.example.test",
			b:    "*.example.org",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SNIHostnamesIntersect(tt.a, tt.b))
			assert.Equal(t, tt.want, SNIHostnamesIntersect(tt.b, tt.a))
		})
	}
}

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
