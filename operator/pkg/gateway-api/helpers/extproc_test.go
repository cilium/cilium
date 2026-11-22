// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestIsExtProcExtensionRef(t *testing.T) {
	tests := []struct {
		name string
		ref  *gatewayv1.LocalObjectReference
		want bool
	}{
		{name: "nil"},
		{name: "ext proc", ref: &gatewayv1.LocalObjectReference{Group: "cilium.io", Kind: "CiliumEnvoyExtProcFilter", Name: "filter"}, want: true},
		{name: "other group", ref: &gatewayv1.LocalObjectReference{Group: "example.com", Kind: "CiliumEnvoyExtProcFilter", Name: "filter"}},
		{name: "other kind", ref: &gatewayv1.LocalObjectReference{Group: "cilium.io", Kind: "OtherFilter", Name: "filter"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExtProcExtensionRef(tt.ref); got != tt.want {
				t.Errorf("IsExtProcExtensionRef(%v) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}
