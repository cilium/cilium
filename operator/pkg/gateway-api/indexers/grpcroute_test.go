// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"log/slog"
	"reflect"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func TestIndexGRPCRouteByGateway(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "parentRef is Gateway",
			obj: &gatewayv1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "valid-gateway",
					Namespace: "default",
				},
				Spec: gatewayv1.GRPCRouteSpec{
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
			obj: &gatewayv1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "valid-gateway",
					Namespace: "default",
				},
				Spec: gatewayv1.GRPCRouteSpec{
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
			obj: &gatewayv1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-parent",
					Namespace: "default",
				},
				Spec: gatewayv1.GRPCRouteSpec{
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
			if got := IndexGRPCRouteByGateway(tt.obj); !slices.Equal(got, tt.want) {
				t.Errorf("IndexGRPCRouteByGateway() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestIndexGRPCRouteByBackendServiceImport(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "Has ServiceImport backend and request mirror refs",
			obj: &gatewayv1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "has-serviceimport",
					Namespace: "default",
				},
				Spec: gatewayv1.GRPCRouteSpec{
					Rules: []gatewayv1.GRPCRouteRule{
						{
							BackendRefs: []gatewayv1.GRPCBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Group:     ptr.To[gatewayv1.Group](mcsapiv1beta1.GroupName),
											Kind:      ptr.To[gatewayv1.Kind]("ServiceImport"),
											Name:      "backend-import",
											Namespace: ptr.To[gatewayv1.Namespace]("backend-ns"),
										},
									},
								},
							},
							Filters: []gatewayv1.GRPCRouteFilter{
								{
									Type: gatewayv1.GRPCRouteFilterRequestMirror,
									RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
										BackendRef: gatewayv1.BackendObjectReference{
											Group: ptr.To[gatewayv1.Group](mcsapiv1beta1.GroupName),
											Kind:  ptr.To[gatewayv1.Kind]("ServiceImport"),
											Name:  "mirror-import",
										},
									},
								},
							},
						},
					},
				},
			},
			want: []string{
				"backend-ns/backend-import",
				"default/mirror-import",
			},
		},
		{
			name: "Has no ServiceImport refs",
			obj: &gatewayv1.GRPCRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-serviceimport",
					Namespace: "default",
				},
				Spec: gatewayv1.GRPCRouteSpec{
					Rules: []gatewayv1.GRPCRouteRule{
						{
							BackendRefs: []gatewayv1.GRPCBackendRef{
								{
									BackendRef: gatewayv1.BackendRef{
										BackendObjectReference: gatewayv1.BackendObjectReference{
											Name: "backend-svc",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IndexGRPCRouteByBackendServiceImport(tt.obj); !slices.Equal(got, tt.want) {
				t.Errorf("IndexGRPCRouteByBackendServiceImport() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateIndexerGRPCRoutebyBackendServiceIncludesRequestMirror(t *testing.T) {
	indexer := GenerateIndexerGRPCRoutebyBackendService(
		fake.NewClientBuilder().WithScheme(helpers.TestScheme(nil)).Build(),
		slog.New(slog.DiscardHandler),
	)

	route := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mirror-route",
			Namespace: "default",
		},
		Spec: gatewayv1.GRPCRouteSpec{
			Rules: []gatewayv1.GRPCRouteRule{
				{
					BackendRefs: []gatewayv1.GRPCBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "primary-svc",
								},
							},
						},
					},
					Filters: []gatewayv1.GRPCRouteFilter{
						{
							Type: gatewayv1.GRPCRouteFilterRequestMirror,
							RequestMirror: &gatewayv1.HTTPRequestMirrorFilter{
								BackendRef: gatewayv1.BackendObjectReference{
									Name:      "mirror-svc",
									Namespace: ptr.To[gatewayv1.Namespace]("other-ns"),
								},
							},
						},
					},
				},
			},
		},
	}

	want := []string{
		"default/primary-svc",
		"other-ns/mirror-svc",
	}
	if got := indexer(route); !slices.Equal(got, want) {
		t.Errorf("GenerateIndexerGRPCRoutebyBackendService() = %v, want %v", got, want)
	}
}

var meshGRPCSplit = &gatewayv1.GRPCRoute{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "mesh-split",
		Namespace: "gateway-conformance-mesh",
	},
	Spec: gatewayv1.GRPCRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{
			ParentRefs: []gatewayv1.ParentReference{
				{
					Group: ptr.To[gatewayv1.Group](""),
					Kind:  ptr.To[gatewayv1.Kind]("Service"),
					Name:  "echo",
				},
			},
		},
		Rules: []gatewayv1.GRPCRouteRule{
			{
				BackendRefs: []gatewayv1.GRPCBackendRef{
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
		},
	},
}

func meshGRPCSplitWithParentRefs(parentRefs []gatewayv1.ParentReference) *gatewayv1.GRPCRoute {
	grpcr := meshGRPCSplit.DeepCopy()

	grpcr.Spec.ParentRefs = parentRefs

	return grpcr
}

func Test_IndexGRPCRouteByGammaService(t *testing.T) {
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
				obj: meshGRPCSplit,
			},
			want: []string{
				"gateway-conformance-mesh/echo",
			},
		},
		{
			name: "no gamma parentRefs",
			args: args{
				obj: meshGRPCSplitWithParentRefs([]gatewayv1.ParentReference{
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
				obj: meshGRPCSplitWithParentRefs([]gatewayv1.ParentReference{
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
				obj: meshGRPCSplitWithParentRefs([]gatewayv1.ParentReference{
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
			name: "not a GRPCRoute",
			args: args{
				obj: &corev1.Service{},
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parentIndexFunc := IndexGRPCRouteByGammaService

			if got := parentIndexFunc(tt.args.obj); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IndexGRPCRouteByGammaService() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
