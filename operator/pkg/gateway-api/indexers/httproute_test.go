// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"reflect"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
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

var meshSplit = &gatewayv1.HTTPRoute{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "mesh-split",
		Namespace: "gateway-conformance-mesh",
	},
	Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{
			ParentRefs: []gatewayv1.ParentReference{
				{
					Group: ptr.To[gatewayv1.Group](""),
					Kind:  ptr.To[gatewayv1.Kind]("Service"),
					Name:  "echo",
				},
			},
		},
		Rules: []gatewayv1.HTTPRouteRule{
			{
				Matches: []gatewayv1.HTTPRouteMatch{
					{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  ptr.To(gatewayv1.PathMatchExact),
							Value: ptr.To("/v1"),
						},
					},
				},
				BackendRefs: []gatewayv1.HTTPBackendRef{
					{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "echo-v1",
								Port: ptr.To[gatewayv1.PortNumber](80),
							},
						},
					},
				},
			},
			{
				Matches: []gatewayv1.HTTPRouteMatch{
					{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  ptr.To(gatewayv1.PathMatchExact),
							Value: ptr.To("/v2"),
						},
					},
				},
				BackendRefs: []gatewayv1.HTTPBackendRef{
					{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "echo-v2",
								Port: ptr.To[gatewayv1.PortNumber](80),
							},
						},
					},
				},
			},
		},
	},
}

func meshSplitWithParentRefs(parentRefs []gatewayv1.ParentReference) *gatewayv1.HTTPRoute {
	hr := meshSplit.DeepCopy()

	hr.Spec.ParentRefs = parentRefs

	return hr
}

func Test_IndexHTTPRouteByGammaService(t *testing.T) {
	type args struct {
		obj client.Object
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "conformance mesh-split",
			args: args{
				obj: meshSplit,
			},
			want: []string{
				"gateway-conformance-mesh/echo",
			},
		},
		{
			name: "no gamma parentRefs",
			args: args{
				obj: meshSplitWithParentRefs([]gatewayv1.ParentReference{
					{
						Name: "default",
					},
				}),
			},
			want: []string{},
		},
		{
			name: "mixed parentRefs",
			args: args{
				obj: meshSplitWithParentRefs([]gatewayv1.ParentReference{
					{
						Name: "default",
					},
					{
						Group: ptr.To[gatewayv1.Group](""),
						Kind:  ptr.To[gatewayv1.Kind]("Service"),
						Name:  "echo",
					},
				}),
			},
			want: []string{
				"gateway-conformance-mesh/echo",
			},
		},
		{
			name: "multiple Gamma parentRefs",
			args: args{
				obj: meshSplitWithParentRefs([]gatewayv1.ParentReference{
					{
						Group: ptr.To[gatewayv1.Group](""),
						Kind:  ptr.To[gatewayv1.Kind]("Service"),
						Name:  "echo",
					},
					{
						Group:     ptr.To[gatewayv1.Group](""),
						Kind:      ptr.To[gatewayv1.Kind]("Service"),
						Name:      "otherservice",
						Namespace: ptr.To[gatewayv1.Namespace]("othernamespace"),
					},
				}),
			},
			want: []string{
				"gateway-conformance-mesh/echo",
				"othernamespace/otherservice",
			},
		},
		{
			name: "not a HTTPRoute",
			args: args{
				obj: &corev1.Service{},
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parentIndexFunc := IndexHTTPRouteByGammaService

			if got := parentIndexFunc(tt.args.obj); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getGammaHTTPRouteParentIndexFunc() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
