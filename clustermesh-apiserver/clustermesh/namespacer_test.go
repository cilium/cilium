// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"testing"

	cmk8s "github.com/cilium/cilium/clustermesh-apiserver/clustermesh/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
)

func TestCiliumIdentityNamespacer_ExtractNamespace(t *testing.T) {
	namespacer := newCiliumIdentityNamespacer()

	tests := []struct {
		name        string
		event       resource.Event[*cilium_api_v2.CiliumIdentity]
		wantNs      string
		wantErr     bool
		errContains string
	}{
		{
			name: "nil object",
			event: resource.Event[*cilium_api_v2.CiliumIdentity]{
				Kind:   resource.Upsert,
				Object: nil,
			},
			wantNs:      "",
			wantErr:     true,
			errContains: "object empty",
		},
		{
			name: "empty namespace",
			event: resource.Event[*cilium_api_v2.CiliumIdentity]{
				Kind: resource.Upsert,
				Object: &cilium_api_v2.CiliumIdentity{
					SecurityLabels: map[string]string{},
				},
			},
			wantNs:      "",
			wantErr:     true,
			errContains: "could not determine namespace",
		},
		{
			name: "valid namespace",
			event: resource.Event[*cilium_api_v2.CiliumIdentity]{
				Kind: resource.Upsert,
				Object: &cilium_api_v2.CiliumIdentity{
					SecurityLabels: map[string]string{
						cmk8s.PodPrefixLbl: "test-namespace",
					},
				},
			},
			wantNs:  "test-namespace",
			wantErr: false,
		},
		{
			name: "valid namespace with delete event",
			event: resource.Event[*cilium_api_v2.CiliumIdentity]{
				Kind: resource.Upsert,
				Object: &cilium_api_v2.CiliumIdentity{
					SecurityLabels: map[string]string{
						cmk8s.PodPrefixLbl: "another-namespace",
					},
				},
			},
			wantNs:  "another-namespace",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := namespacer.ExtractNamespace(tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractNamespace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errContains != "" {
				if err.Error() != tt.errContains {
					t.Errorf("ExtractNamespace() error = %v, want error containing %v", err, tt.errContains)
				}
			}
			if ns != tt.wantNs {
				t.Errorf("ExtractNamespace() namespace = %v, want %v", ns, tt.wantNs)
			}
		})
	}
}

func TestCiliumEndpointNamespacer_ExtractNamespace(t *testing.T) {
	namespacer := newCiliumEndpointNamespacer()

	tests := []struct {
		name        string
		event       resource.Event[*types.CiliumEndpoint]
		wantNs      string
		wantErr     bool
		errContains string
	}{
		{
			name: "nil object",
			event: resource.Event[*types.CiliumEndpoint]{
				Kind:   resource.Upsert,
				Object: nil,
			},
			wantNs:      "",
			wantErr:     true,
			errContains: "object empty",
		},
		{
			name: "empty namespace",
			event: resource.Event[*types.CiliumEndpoint]{
				Kind: resource.Upsert,
				Object: &types.CiliumEndpoint{
					ObjectMeta: slim_metav1.ObjectMeta{
						Namespace: "",
					},
				},
			},
			wantNs:      "",
			wantErr:     true,
			errContains: "could not determine namespace",
		},
		{
			name: "valid namespace",
			event: resource.Event[*types.CiliumEndpoint]{
				Kind: resource.Upsert,
				Object: &types.CiliumEndpoint{
					ObjectMeta: slim_metav1.ObjectMeta{
						Namespace: "test-namespace",
					},
				},
			},
			wantNs:  "test-namespace",
			wantErr: false,
		},
		{
			name: "valid namespace with delete event",
			event: resource.Event[*types.CiliumEndpoint]{
				Kind: resource.Upsert,
				Object: &types.CiliumEndpoint{
					ObjectMeta: slim_metav1.ObjectMeta{
						Namespace: "another-namespace",
					},
				},
			},
			wantNs:  "another-namespace",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := namespacer.ExtractNamespace(tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractNamespace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errContains != "" {
				if err.Error() != tt.errContains {
					t.Errorf("ExtractNamespace() error = %v, want error containing %v", err, tt.errContains)
				}
			}
			if ns != tt.wantNs {
				t.Errorf("ExtractNamespace() namespace = %v, want %v", ns, tt.wantNs)
			}
		})
	}
}

func TestCiliumEndpointSliceNamespacer_ExtractNamespace(t *testing.T) {
	namespacer := newCiliumEndpointSliceNamespacer()

	tests := []struct {
		name        string
		event       resource.Event[*cilium_api_v2a1.CiliumEndpointSlice]
		wantNs      string
		wantErr     bool
		errContains string
	}{
		{
			name: "nil object",
			event: resource.Event[*cilium_api_v2a1.CiliumEndpointSlice]{
				Kind:   resource.Upsert,
				Object: nil,
			},
			wantNs:      "",
			wantErr:     true,
			errContains: "object empty",
		},
		{
			name: "empty namespace",
			event: resource.Event[*cilium_api_v2a1.CiliumEndpointSlice]{
				Kind: resource.Upsert,
				Object: &cilium_api_v2a1.CiliumEndpointSlice{
					Namespace: "",
				},
			},
			wantNs:      "",
			wantErr:     true,
			errContains: "could not determine namespace",
		},
		{
			name: "valid namespace",
			event: resource.Event[*cilium_api_v2a1.CiliumEndpointSlice]{
				Kind: resource.Upsert,
				Object: &cilium_api_v2a1.CiliumEndpointSlice{
					Namespace: "test-namespace",
				},
			},
			wantNs:  "test-namespace",
			wantErr: false,
		},
		{
			name: "valid namespace with delete event",
			event: resource.Event[*cilium_api_v2a1.CiliumEndpointSlice]{
				Kind: resource.Upsert,
				Object: &cilium_api_v2a1.CiliumEndpointSlice{
					Namespace: "another-namespace",
				},
			},
			wantNs:  "another-namespace",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := namespacer.ExtractNamespace(tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractNamespace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errContains != "" {
				if err.Error() != tt.errContains {
					t.Errorf("ExtractNamespace() error = %v, want error containing %v", err, tt.errContains)
				}
			}
			if ns != tt.wantNs {
				t.Errorf("ExtractNamespace() namespace = %v, want %v", ns, tt.wantNs)
			}
		})
	}
}
