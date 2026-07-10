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
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"
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
			name: "GatewayClass",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    GatewayClassKind,
			},
			want: &gatewayv1.GatewayClass{},
		},
		{
			name: "Gateway",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    GatewayKind,
			},
			want: &gatewayv1.Gateway{},
		},
		{
			name: "TLSRoute",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    TLSRouteKind,
			},
			want: &gatewayv1.TLSRoute{},
		},
		{
			name: "HTTPRoute",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    HTTPRouteKind,
			},
			want: &gatewayv1.HTTPRoute{},
		},
		{
			name: "GRPCRoute",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    GRPCRouteKind,
			},
			want: &gatewayv1.GRPCRoute{},
		},
		{
			name: "ReferenceGrant",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    ReferenceGrantKind,
			},
			want: &gatewayv1.ReferenceGrant{},
		},
		{
			name: "BackendTLSPolicy",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    BackendTLSPolicyKind,
			},
			want: &gatewayv1.BackendTLSPolicy{},
		},
		{
			name: "TCPRoute",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    TCPRouteKind,
			},
			want: &gatewayv1.TCPRoute{},
		},
		{
			name: "UDPRoute",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    UDPRouteKind,
			},
			want: &gatewayv1.UDPRoute{},
		},
		{
			name: "ListenerSet",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    ListenerSetKind,
			},
			want: &gatewayv1.ListenerSet{},
		},
		{
			name: "ServiceImport",
			gvk: schema.GroupVersionKind{
				Group:   mcsapiv1beta1.GroupVersion.Group,
				Version: mcsapiv1beta1.GroupVersion.Version,
				Kind:    ServiceImportKind,
			},
			want: &mcsapiv1beta1.ServiceImport{},
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

func TestGetConcreteListObject(t *testing.T) {
	tests := []struct {
		name string
		gvk  schema.GroupVersionKind
		want runtime.Object
	}{
		{
			name: "GatewayClassList",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    GatewayClassKind,
			},
			want: &gatewayv1.GatewayClassList{},
		},
		{
			name: "GatewayList",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    GatewayKind,
			},
			want: &gatewayv1.GatewayList{},
		},
		{
			name: "TLSRouteList",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    TLSRouteKind,
			},
			want: &gatewayv1.TLSRouteList{},
		},
		{
			name: "HTTPRouteList",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    HTTPRouteKind,
			},
			want: &gatewayv1.HTTPRouteList{},
		},
		{
			name: "GRPCRouteList",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    GRPCRouteKind,
			},
			want: &gatewayv1.GRPCRouteList{},
		},
		{
			name: "ReferenceGrantList",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    ReferenceGrantKind,
			},
			want: &gatewayv1.ReferenceGrantList{},
		},
		{
			name: "BackendTLSPolicyList",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    BackendTLSPolicyKind,
			},
			want: &gatewayv1.BackendTLSPolicyList{},
		},
		{
			name: "TCPRouteList",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    TCPRouteKind,
			},
			want: &gatewayv1.TCPRouteList{},
		},
		{
			name: "UDPRouteList",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    UDPRouteKind,
			},
			want: &gatewayv1.UDPRouteList{},
		},
		{
			name: "ListenerSetList",
			gvk: schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    ListenerSetKind,
			},
			want: &gatewayv1.ListenerSetList{},
		},
		{
			name: "ServiceImportList",
			gvk: schema.GroupVersionKind{
				Group:   mcsapiv1beta1.GroupVersion.Group,
				Version: mcsapiv1beta1.GroupVersion.Version,
				Kind:    ServiceImportKind,
			},
			want: &mcsapiv1beta1.ServiceImportList{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetConcreteListObject(tt.gvk)
			if reflect.TypeOf(got) != reflect.TypeOf(tt.want) {
				t.Errorf("got a %T, expected a %T", got, tt.want)
			}
		})
	}
}
