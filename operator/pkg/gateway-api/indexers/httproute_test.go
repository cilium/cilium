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
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

func TestIndexHTTPRouteByGateway(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "parentRef is Gateway",
			obj: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "valid-gateway",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
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
			obj: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "valid-gateway",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
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
			obj: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-parent",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
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
			if got := IndexHTTPRouteByGateway(tt.obj); !slices.Equal(got, tt.want) {
				t.Errorf("IndexHTTPRouteByGateway() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestIndexHTTPRouteByBackendServiceImport(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "Has ServiceImport backendRef",
			obj: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "has-serviceimport",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:      "valid",
								Namespace: ptr.To[gatewayv1.Namespace]("default"),
							},
						},
					},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Group:     ptr.To[gatewayv1.Group](mcsapiv1alpha1.GroupName),
											Kind:      ptr.To[gatewayv1.Kind]("ServiceImport"),
											Name:      "valid-serviceImport",
											Namespace: ptr.To[gatewayv1.Namespace]("default"),
										},
									},
								},
							},
						},
					},
				},
			},
			want: []string{
				"default/valid-serviceImport",
			},
		},
		{
			name: "Has ServiceImport backend with nil namespace",
			obj: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "has-serviceimport",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:      "valid",
								Namespace: ptr.To[gatewayv1.Namespace]("default"),
							},
						},
					},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Group: ptr.To[gatewayv1.Group](mcsapiv1alpha1.GroupName),
											Kind:  ptr.To[gatewayv1.Kind]("ServiceImport"),
											Name:  "valid-serviceImport",
										},
									},
								},
							},
						},
					},
				},
			},
			want: []string{
				"default/valid-serviceImport",
			},
		},
		{
			name: "Has Service backendRef",
			obj: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "has-serviceimport",
					Namespace: "default",
				},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:      "valid",
								Namespace: ptr.To[gatewayv1.Namespace]("default"),
							},
						},
					},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							BackendRefs: []gatewayv1.HTTPBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name:      "valid-service",
											Namespace: ptr.To[gatewayv1.Namespace]("default"),
										},
									},
								},
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
			if got := IndexHTTPRouteByBackendServiceImport(tt.obj); !slices.Equal(got, tt.want) {
				t.Errorf("IndexHTTPRouteByBackendServiceImport() = %v, want %v", got, tt.want)
			}
		})
	}
}
