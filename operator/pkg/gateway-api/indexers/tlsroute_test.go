// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

func TestIndexTLSRouteByGateway(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "parentRef is Gateway",
			obj: &gatewayv1alpha2.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "valid-gateway",
					Namespace: "default",
				},
				Spec: gatewayv1alpha2.TLSRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:      "valid",
								Namespace: ptr.To[gatewayv1.Namespace]("default"),
							},
						},
					},
				},
			},
			want: []string{
				"default/valid",
			},
		},
		{
			name: "parentRef is a Gateway, nil namespace",
			obj: &gatewayv1alpha2.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "valid-gateway",
					Namespace: "default",
				},
				Spec: gatewayv1alpha2.TLSRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name: "valid-nil-namespace",
							},
						},
					},
				},
			},
			want: []string{
				"default/valid-nil-namespace",
			},
		},
		{
			name: "parentRef is not a Gateway",
			obj: &gatewayv1alpha2.TLSRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-parent",
					Namespace: "default",
				},
				Spec: gatewayv1alpha2.TLSRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:      "invalid",
								Namespace: ptr.To[gatewayv1.Namespace]("default"),
								Kind:      ptr.To[gatewayv1.Kind]("OtherKind"),
								Group:     ptr.To[gatewayv1.Group]("somegroup.io"),
							},
						},
					},
				},
			},
			want: []string(nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IndexTLSRouteByGateway(tt.obj); !slices.Equal(got, tt.want) {
				t.Errorf("IndexTLSRouteByGateway() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
