// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestObjectEqual(t *testing.T) {
	gatewayv1ApiVersion := gatewayv1.GroupVersion.Group + "/" + gatewayv1.GroupVersion.Version

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		a       client.Object
		b       client.Object
		want    bool
		wantErr bool
	}{
		{
			name:    "Empty objects",
			a:       &gatewayv1.HTTPRoute{},
			b:       &gatewayv1.HTTPRoute{},
			want:    true,
			wantErr: false,
		},
		{
			name: "Simple Equality",
			a: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "equal",
					Namespace:  "default",
					Generation: 1,
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: gatewayv1ApiVersion,
					Kind:       "HTTPRoute",
				},
			},
			b: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "equal",
					Namespace:  "default",
					Generation: 1,
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: gatewayv1ApiVersion,
					Kind:       "HTTPRoute",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Simple Inequality",
			a: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "equal",
					Namespace:  "default",
					Generation: 1,
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: gatewayv1ApiVersion,
					Kind:       "HTTPRoute",
				},
			},
			b: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "notequal",
					Namespace:  "default",
					Generation: 1,
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: gatewayv1ApiVersion,
					Kind:       "HTTPRoute",
				},
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "Same object, different version",
			a: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "equal",
					Namespace:  "default",
					Generation: 1,
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: gatewayv1ApiVersion,
					Kind:       "HTTPRoute",
				},
			},
			b: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "equal",
					Namespace:  "default",
					Generation: 2,
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: gatewayv1ApiVersion,
					Kind:       "HTTPRoute",
				},
			},
			want:    true,
			wantErr: true,
		},
		{
			name: "Different Kinds",
			a: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "equal",
					Namespace:  "default",
					Generation: 1,
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Service",
				},
			},
			b: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "equal",
					Namespace:  "default",
					Generation: 1,
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: gatewayv1ApiVersion,
					Kind:       "HTTPRoute",
				},
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "Equal Services",
			a: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "equal",
					Namespace:  "default",
					Generation: 1,
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Service",
				},
			},
			b: &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "equal",
					Namespace:  "default",
					Generation: 1,
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: gatewayv1ApiVersion,
					Kind:       "HTTPRoute",
				},
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := ObjectsEqual(tt.a, tt.b)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ObjectEqual() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("ObjectEqual() succeeded unexpectedly")
			}
			// TODO: update the condition below to compare got with tt.want.
			if got != tt.want {
				t.Errorf("ObjectEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}
