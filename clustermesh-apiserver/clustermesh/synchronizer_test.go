// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmnamespace "github.com/cilium/cilium/pkg/clustermesh/namespace"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
)

func TestResourceHandler(t *testing.T) {
	tests := []struct {
		name              string
		event             resource.Event[*ciliumv2.CiliumIdentity]
		globalNamespaces  []*slim_corev1.Namespace
		expectedNamespace string
		expectedProcess   bool
		expectErr         bool
	}{
		{
			name: "CiliumIdentity in global namespace - Upsert",
			event: resource.Event[*ciliumv2.CiliumIdentity]{
				Kind: resource.Upsert,
				Key:  resource.Key{Name: "id1", Namespace: "kube-system"},
				Object: &ciliumv2.CiliumIdentity{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "id1",
						Namespace: "kube-system",
					},
					SecurityLabels: map[string]string{
						"k8s:io.kubernetes.pod.namespace": "kube-system",
					},
				},
			},
			globalNamespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "kube-system",
						Annotations: map[string]string{
							"clustermesh.cilium.io/global": "true",
						},
					},
				},
			},
			expectedNamespace: "kube-system",
			expectedProcess:   true,
		},

		{
			name: "CiliumIdentity in global namespace - Upsert but namespace not in store yet",
			event: resource.Event[*ciliumv2.CiliumIdentity]{
				Kind: resource.Upsert,
				Key:  resource.Key{Name: "id1", Namespace: "kube-system"},
				Object: &ciliumv2.CiliumIdentity{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "id1",
						Namespace: "kube-system",
					},
					SecurityLabels: map[string]string{
						"k8s:io.kubernetes.pod.namespace": "kube-system",
					},
				},
			},
			globalNamespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "default",
						Annotations: map[string]string{
							"clustermesh.cilium.io/global": "true",
						},
					},
				},
			},
			expectedNamespace: "kube-system",
			expectedProcess:   false,
			expectErr:         true,
		},
		{
			name: "CiliumIdentity in non-global namespace - Upsert",
			event: resource.Event[*ciliumv2.CiliumIdentity]{
				Kind: resource.Upsert,
				Key:  resource.Key{Name: "id2", Namespace: "default"},
				Object: &ciliumv2.CiliumIdentity{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "id2",
						Namespace: "default",
					},
					SecurityLabels: map[string]string{
						"k8s:io.kubernetes.pod.namespace": "default",
					},
				},
			},
			globalNamespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "default",
						Annotations: map[string]string{
							"clustermesh.cilium.io/global": "false",
						},
					},
				},
			},
			expectedNamespace: "default",
			expectedProcess:   false,
		},
		{
			name: "CiliumIdentity in global namespace - Delete",
			event: resource.Event[*ciliumv2.CiliumIdentity]{
				Kind: resource.Delete,
				Key:  resource.Key{Name: "id3", Namespace: "kube-system"},
				Object: &ciliumv2.CiliumIdentity{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "id3",
						Namespace: "kube-system",
					},
					SecurityLabels: map[string]string{
						"k8s:io.kubernetes.pod.namespace": "kube-system",
					},
				},
			},
			globalNamespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "kube-system",
						Annotations: map[string]string{
							"clustermesh.cilium.io/global": "true",
						},
					},
				},
			},
			expectedNamespace: "", // For Delete, namespace is not relevant
			expectedProcess:   true,
		},
		{
			name: "CiliumIdentity in non-global namespace - Delete",
			event: resource.Event[*ciliumv2.CiliumIdentity]{
				Kind: resource.Delete,
				Key:  resource.Key{Name: "id4", Namespace: "default"},
				Object: &ciliumv2.CiliumIdentity{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "id4",
						Namespace: "default",
					},
					SecurityLabels: map[string]string{
						"k8s:io.kubernetes.pod.namespace": "default",
					},
				},
			},
			globalNamespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "kube-system",
						Annotations: map[string]string{
							"clustermesh.cilium.io/global": "false",
						},
					},
				},
			},
			expectedNamespace: "", // For Delete, namespace is not relevant
			expectedProcess:   true,
		},
		{
			name: "CiliumIdentity with no namespace",
			event: resource.Event[*ciliumv2.CiliumIdentity]{
				Kind: resource.Upsert,
				Key:  resource.Key{Name: "id5"},
				Object: &ciliumv2.CiliumIdentity{
					ObjectMeta: metav1.ObjectMeta{
						Name: "id5",
					},
				},
			},
			globalNamespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "kube-system",
						Annotations: map[string]string{
							"clustermesh.cilium.io/global": "true",
						},
					},
				},
			},
			expectedNamespace: "",
			expectedProcess:   false,
			expectErr:         true,
		},
		{
			name: "CiliumIdentity with nil object",
			event: resource.Event[*ciliumv2.CiliumIdentity]{
				Kind:   resource.Upsert,
				Key:    resource.Key{Name: "id6", Namespace: "kube-system"},
				Object: nil,
			},
			globalNamespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "kube-system",
						Annotations: map[string]string{
							"clustermesh.cilium.io/global": "true",
						},
					},
				},
			},
			expectedNamespace: "",
			expectedProcess:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockManager := cmnamespace.NewMockNamespaceManager(false, tt.globalNamespaces...)
			params := syncParams[*ciliumv2.CiliumIdentity]{
				NamespaceManager: mockManager,
			}

			namespace, process, err := resourceHandler(params, tt.event)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedNamespace, namespace, "namespace mismatch")
			assert.Equal(t, tt.expectedProcess, process, "process flag mismatch")
		})
	}
}

func TestResourceHandler_CiliumEndpoint(t *testing.T) {
	tests := []struct {
		name              string
		event             resource.Event[*types.CiliumEndpoint]
		globalNamespaces  []*slim_corev1.Namespace
		expectedNamespace string
		expectedProcess   bool
	}{
		{
			name: "CiliumEndpoint in global namespace - Upsert",
			event: resource.Event[*types.CiliumEndpoint]{
				Kind: resource.Upsert,
				Key:  resource.Key{Name: "ep1", Namespace: "kube-system"},
				Object: &types.CiliumEndpoint{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "ep1",
						Namespace: "kube-system",
					},
				},
			},
			globalNamespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "kube-system",
						Annotations: map[string]string{
							"clustermesh.cilium.io/global": "true",
						},
					},
				},
			},
			expectedNamespace: "kube-system",
			expectedProcess:   true,
		},
		{
			name: "CiliumEndpoint in non-global namespace - Delete",
			event: resource.Event[*types.CiliumEndpoint]{
				Kind: resource.Delete,
				Key:  resource.Key{Name: "ep2", Namespace: "default"},
				Object: &types.CiliumEndpoint{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "ep2",
						Namespace: "default",
					},
				},
			},
			globalNamespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "kube-system",
						Annotations: map[string]string{
							"clustermesh.cilium.io/global": "true",
						},
					},
				},
			},
			expectedNamespace: "",
			expectedProcess:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockManager := cmnamespace.NewMockNamespaceManager(false, tt.globalNamespaces...)

			params := syncParams[*types.CiliumEndpoint]{
				NamespaceManager: mockManager,
			}

			namespace, process, err := resourceHandler(params, tt.event)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedNamespace, namespace, "namespace mismatch")
			assert.Equal(t, tt.expectedProcess, process, "process flag mismatch")
		})
	}
}

func TestResourceHandler_CiliumEndpointSlice(t *testing.T) {
	tests := []struct {
		name              string
		event             resource.Event[*ciliumv2alpha1.CiliumEndpointSlice]
		globalNamespaces  []*slim_corev1.Namespace
		expectedNamespace string
		expectedProcess   bool
	}{
		{
			name: "CiliumEndpointSlice in global namespace - Upsert",
			event: resource.Event[*ciliumv2alpha1.CiliumEndpointSlice]{
				Kind: resource.Upsert,
				Key:  resource.Key{Name: "ces1", Namespace: "kube-system"},
				Object: &ciliumv2alpha1.CiliumEndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ces1",
						Namespace: "kube-system",
					},
					Namespace: "kube-system",
				},
			},
			globalNamespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "kube-system",
						Annotations: map[string]string{
							"clustermesh.cilium.io/global": "true",
						},
					},
				},
			},
			expectedNamespace: "kube-system",
			expectedProcess:   true,
		},
		{
			name: "CiliumEndpointSlice in non-global namespace - Upsert",
			event: resource.Event[*ciliumv2alpha1.CiliumEndpointSlice]{
				Kind: resource.Upsert,
				Key:  resource.Key{Name: "ces2", Namespace: "default"},
				Object: &ciliumv2alpha1.CiliumEndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ces2",
						Namespace: "default",
					},
					Namespace: "default",
				},
			},
			globalNamespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "default",
						Annotations: map[string]string{
							"clustermesh.cilium.io/global": "false",
						},
					},
				},
			},
			expectedNamespace: "default",
			expectedProcess:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := cmnamespace.NewMockNamespaceManager(false, tt.globalNamespaces...)

			params := syncParams[*ciliumv2alpha1.CiliumEndpointSlice]{
				NamespaceManager: m,
			}

			namespace, process, err := resourceHandler(params, tt.event)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedNamespace, namespace, "namespace mismatch")
			assert.Equal(t, tt.expectedProcess, process, "process flag mismatch")
		})
	}
}
