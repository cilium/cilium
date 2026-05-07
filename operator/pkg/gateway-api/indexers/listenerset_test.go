// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestIndexListenerSetByGateway(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "parentRef with no namespace defaults to ListenerSet namespace",
			obj: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-listenerset",
					Namespace: "default",
				},
				Spec: gatewayv1.ListenerSetSpec{
					ParentRef: gatewayv1.ParentGatewayReference{
						Name: "my-gateway",
					},
				},
			},
			want: []string{"default/my-gateway"},
		},
		{
			name: "parentRef with explicit namespace",
			obj: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-listenerset",
					Namespace: "default",
				},
				Spec: gatewayv1.ListenerSetSpec{
					ParentRef: gatewayv1.ParentGatewayReference{
						Name:      "my-gateway",
						Namespace: ptr.To[gatewayv1.Namespace]("infra"),
					},
				},
			},
			want: []string{"infra/my-gateway"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IndexListenerSetByGateway(tt.obj)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IndexListenerSetByGateway() = %v, want %v", got, tt.want)
			}
		})
	}
}
