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

func TestIndexBTLSPolicyByConfigMap(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		rawObj client.Object
		want   []string
	}{
		{
			name: "One valid Configmap",
			rawObj: &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "btlsp",
					Namespace: "default",
				},
				Spec: gatewayv1.BackendTLSPolicySpec{
					Validation: gatewayv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gatewayv1.LocalObjectReference{
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("ConfigMap"),
								Name:  gatewayv1.ObjectName("ca-cert"),
							},
						},
					},
				},
			},
			want: []string{
				"default/ca-cert",
			},
		},
		{
			name: "Two valid Configmaps",
			rawObj: &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "btlsp",
					Namespace: "default",
				},
				Spec: gatewayv1.BackendTLSPolicySpec{
					Validation: gatewayv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gatewayv1.LocalObjectReference{
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("ConfigMap"),
								Name:  gatewayv1.ObjectName("ca-cert"),
							},
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("ConfigMap"),
								Name:  gatewayv1.ObjectName("ca-cert-2"),
							},
						},
					},
				},
			},
			want: []string{
				"default/ca-cert",
				"default/ca-cert-2",
			},
		},
		{
			name: "No CACertificateRefs",
			rawObj: &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "btlsp",
					Namespace: "default",
				},
				Spec: gatewayv1.BackendTLSPolicySpec{
					Validation: gatewayv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gatewayv1.LocalObjectReference{},
					},
				},
			},
			want: []string{},
		},
		{
			name: "One entry, not Configmap",
			rawObj: &gatewayv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "btlsp",
					Namespace: "default",
				},
				Spec: gatewayv1.BackendTLSPolicySpec{
					Validation: gatewayv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gatewayv1.LocalObjectReference{
							{
								Group: gatewayv1.Group(""),
								Kind:  gatewayv1.Kind("SomeOtherKind"),
								Name:  gatewayv1.ObjectName("ca-cert"),
							},
						},
					},
				},
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IndexBTLSPolicyByConfigMap(tt.rawObj)
			if !slices.Equal(tt.want, got) {
				t.Errorf("IndexBTLSPolicyByConfigMap() = %v, want %v", got, tt.want)
			}
		})
	}
}
