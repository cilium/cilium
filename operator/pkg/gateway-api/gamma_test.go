// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"reflect"
	"testing"

	"github.com/cilium/hive/hivetest"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func Test_getGammaHTTPRouteParentIndexFunc(t *testing.T) {
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
			logger := hivetest.Logger(t)
			parentIndexFunc := getGammaHTTPRouteParentIndexFunc(logger)

			if got := parentIndexFunc(tt.args.obj); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getGammaHTTPRouteParentIndexFunc() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
