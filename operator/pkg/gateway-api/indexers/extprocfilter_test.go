// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestIndexHTTPRouteByExtProcFilter(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "extensionRef to CiliumEnvoyExtProcFilter",
			obj: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterExtensionRef,
									ExtensionRef: &gatewayv1.LocalObjectReference{
										Group: "cilium.io",
										Kind:  "CiliumEnvoyExtProcFilter",
										Name:  "my-filter",
									},
								},
							},
						},
					},
				},
			},
			want: []string{"default/my-filter"},
		},
		{
			name: "extensionRef to a different kind is ignored",
			obj: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterExtensionRef,
									ExtensionRef: &gatewayv1.LocalObjectReference{
										Group: "cilium.io",
										Kind:  "SomeOtherKind",
										Name:  "my-filter",
									},
								},
							},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "non-extensionRef filters are ignored",
			obj: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterRequestMirror,
									RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
										BackendRef: gatewayv1.BackendObjectReference{
											Name: "mirror-svc",
										},
									},
								},
							},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "multiple rules and filters",
			obj: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					Rules: []gatewayv1.HTTPRouteRule{
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterExtensionRef,
									ExtensionRef: &gatewayv1.LocalObjectReference{
										Group: "cilium.io",
										Kind:  "CiliumEnvoyExtProcFilter",
										Name:  "filter-a",
									},
								},
							},
						},
						{
							Filters: []gatewayv1.HTTPRouteFilter{
								{
									Type: gatewayv1.HTTPRouteFilterExtensionRef,
									ExtensionRef: &gatewayv1.LocalObjectReference{
										Group: "cilium.io",
										Kind:  "CiliumEnvoyExtProcFilter",
										Name:  "filter-b",
									},
								},
							},
						},
					},
				},
			},
			want: []string{"default/filter-a", "default/filter-b"},
		},
		{
			name: "not an HTTPRoute",
			obj:  &gatewayv1.GRPCRoute{},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IndexHTTPRouteByExtProcFilter(tt.obj); !slices.Equal(got, tt.want) {
				t.Errorf("IndexHTTPRouteByExtProcFilter() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestIndexGRPCRouteByExtProcFilter(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "extensionRef to CiliumEnvoyExtProcFilter",
			obj: &gatewayv1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route",
					Namespace: "default",
				},
				Spec: gatewayv1.GRPCRouteSpec{
					Rules: []gatewayv1.GRPCRouteRule{
						{
							Filters: []gatewayv1.GRPCRouteFilter{
								{
									Type: gatewayv1.GRPCRouteFilterExtensionRef,
									ExtensionRef: &gatewayv1.LocalObjectReference{
										Group: "cilium.io",
										Kind:  "CiliumEnvoyExtProcFilter",
										Name:  "my-filter",
									},
								},
							},
						},
					},
				},
			},
			want: []string{"default/my-filter"},
		},
		{
			name: "extensionRef to a different kind is ignored",
			obj: &gatewayv1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "route",
					Namespace: "default",
				},
				Spec: gatewayv1.GRPCRouteSpec{
					Rules: []gatewayv1.GRPCRouteRule{
						{
							Filters: []gatewayv1.GRPCRouteFilter{
								{
									Type: gatewayv1.GRPCRouteFilterExtensionRef,
									ExtensionRef: &gatewayv1.LocalObjectReference{
										Group: "cilium.io",
										Kind:  "SomeOtherKind",
										Name:  "my-filter",
									},
								},
							},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "not a GRPCRoute",
			obj:  &gatewayv1.HTTPRoute{},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IndexGRPCRouteByExtProcFilter(tt.obj); !slices.Equal(got, tt.want) {
				t.Errorf("IndexGRPCRouteByExtProcFilter() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
