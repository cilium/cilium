// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package helpers

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
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
			name: "service kind with group core",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind:  ptr.To[gatewayv1.Kind]("Service"),
					Group: ptr.To[gatewayv1.Group]("core"),
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

func TestIsGammaServiceEqual(t *testing.T) {
	type args struct {
		parent          gatewayv1.ParentReference
		gammaService    *corev1.Service
		objectNamespace string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "default kind",
			args: args{
				parent:       gatewayv1.ParentReference{},
				gammaService: &corev1.Service{},
			},
			want: false,
		},
		{
			name: "gateway kind",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind: ptr.To[gatewayv1.Kind]("Gateway"),
				},
				gammaService: &corev1.Service{},
			},
			want: false,
		},
		{
			name: "service kind but no group",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind: ptr.To[gatewayv1.Kind]("Service"),
				},
				gammaService: &corev1.Service{},
			},
			want: false,
		},
		{
			name: "service kind with namespace supplied in parentRef",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind:      ptr.To[gatewayv1.Kind]("Service"),
					Group:     ptr.To[gatewayv1.Group](""),
					Namespace: ptr.To[gatewayv1.Namespace]("parentRefNS"),
					Name:      "testgamma",
				},
				gammaService: &corev1.Service{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Service",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "parentRefNS",
						Name:      "testgamma",
					},
				},
			},
			want: true,
		},
		{
			name: "service kind with no namespace supplied in parentRef",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind:  ptr.To[gatewayv1.Kind]("Service"),
					Group: ptr.To[gatewayv1.Group](""),
					Name:  "testgamma",
				},
				gammaService: &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "objNS",
						Name:      "testgamma",
					},
					TypeMeta: metav1.TypeMeta{
						Kind:       "Service",
						APIVersion: "v1",
					},
				},
				objectNamespace: "objNS",
			},
			want: true,
		},
		{
			name: "service kind, no namespace supplied in parentRef, non-matching objectNamespace",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind:  ptr.To[gatewayv1.Kind]("Service"),
					Group: ptr.To[gatewayv1.Group](""),
					Name:  "testgamma",
				},
				gammaService: &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "testns",
						Name:      "testgamma",
					},
					TypeMeta: metav1.TypeMeta{
						Kind:       "Service",
						APIVersion: "v1",
					},
				},
				objectNamespace: "someotherns",
			},
			want: false,
		},
		{
			name: "service kind with namespace supplied in parentRef, diff name",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind:      ptr.To[gatewayv1.Kind]("Service"),
					Group:     ptr.To[gatewayv1.Group](""),
					Namespace: ptr.To[gatewayv1.Namespace]("parentRefNS"),
					Name:      "othername",
				},
				gammaService: &corev1.Service{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Service",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "parentRefNS",
						Name:      "testgamma",
					},
				},
			},
			want: false,
		},
		{
			name: "something else, diff kind",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind:  ptr.To[gatewayv1.Kind]("AnotherKind"),
					Group: ptr.To[gatewayv1.Group](""),
				},
				gammaService: &corev1.Service{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Service",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "parentRefNS",
						Name:      "testgamma",
					},
				},
			},
			want: false,
		},
		{
			name: "something else, diff group",
			args: args{
				parent: gatewayv1.ParentReference{
					Kind:  ptr.To[gatewayv1.Kind]("Service"),
					Group: ptr.To[gatewayv1.Group]("badgroup.io"),
				},
				gammaService: &corev1.Service{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Service",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "parentRefNS",
						Name:      "testgamma",
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsGammaServiceEqual(tt.args.parent, tt.args.gammaService, tt.args.objectNamespace)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGetConcreteObject(t *testing.T) {
	tests := []struct {
		name string
		gvk  schema.GroupVersionKind
		want runtime.Object
	}{
		{
			name: "TLSRoute",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1alpha2.GroupVersion.Group,
				Version: gatewayv1alpha2.GroupVersion.Version,
				Kind:    TLSRouteKind,
			},
			want: &gatewayv1alpha2.TLSRoute{},
		},
		{
			name: "TLSRouteList",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1alpha2.GroupVersion.Group,
				Version: gatewayv1alpha2.GroupVersion.Version,
				Kind:    TLSRouteListKind,
			},
			want: &gatewayv1alpha2.TLSRouteList{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetConcreteObject(tt.gvk)
			if reflect.TypeOf(got) != reflect.TypeOf(tt.want) {
				t.Errorf("got a %T, expected a %T", got, tt.want)
			}
		})
	}
}
