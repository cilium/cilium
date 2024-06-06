// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestIsGammaService(t *testing.T) {
	type args struct {
		parent gatewayv1.ParentReference
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "default kind",
			args: args{
				parent: gatewayv1.ParentReference{},
			},
			want: false,
		},
		{
			name: "gateway kind",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind: ptr.To[gatewayv1.Kind]("Gateway"),
				},
			},
			want: false,
		},
		{
			name: "service kind but no group",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind: ptr.To[gatewayv1.Kind]("Service"),
				},
			},
			want: false,
		},
		{
			name: "service kind",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind:  ptr.To[gatewayv1.Kind]("Service"),
					Group: ptr.To[gatewayv1.Group](""),
				},
			},
			want: true,
		},
		{
			name: "something else",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind: ptr.To[gatewayv1.Kind]("AnotherKind"),
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsGammaService(tt.args.parent)
			require.Equal(t, tt.want, got)
		})
	}
}
