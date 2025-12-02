// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namespace

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/annotation"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestIsGlobalNamespace(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		namespace   *slim_corev1.Namespace
		expected    bool
		description string
	}{
		{
			name: "nil namespace",
			config: Config{
				EnableDefaultGlobalNamespace: true,
			},
			namespace:   nil,
			expected:    false,
			description: "nil namespace should always return false",
		},
		{
			name: "annotation true with default false",
			config: Config{
				EnableDefaultGlobalNamespace: false,
			},
			namespace: &slim_corev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "test-ns",
					Annotations: map[string]string{
						annotation.GlobalNamespace: "true",
					},
				},
			},
			expected:    true,
			description: "annotation=true should override default=false",
		},
		{
			name: "annotation false with default true",
			config: Config{
				EnableDefaultGlobalNamespace: true,
			},
			namespace: &slim_corev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "test-ns",
					Annotations: map[string]string{
						annotation.GlobalNamespace: "false",
					},
				},
			},
			expected:    false,
			description: "annotation=false should override default=true",
		},
		{
			name: "annotation true uppercase",
			config: Config{
				EnableDefaultGlobalNamespace: false,
			},
			namespace: &slim_corev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "test-ns",
					Annotations: map[string]string{
						annotation.GlobalNamespace: "TRUE",
					},
				},
			},
			expected:    true,
			description: "annotation value should be case-insensitive",
		},
		{
			name: "annotation mixed case",
			config: Config{
				EnableDefaultGlobalNamespace: false,
			},
			namespace: &slim_corev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "test-ns",
					Annotations: map[string]string{
						annotation.GlobalNamespace: "TrUe",
					},
				},
			},
			expected:    true,
			description: "annotation value should be case-insensitive",
		},
		{
			name: "no annotation with default true",
			config: Config{
				EnableDefaultGlobalNamespace: true,
			},
			namespace: &slim_corev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "test-ns",
				},
			},
			expected:    true,
			description: "no annotation should fall back to default=true",
		},
		{
			name: "no annotation with default false",
			config: Config{
				EnableDefaultGlobalNamespace: false,
			},
			namespace: &slim_corev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "test-ns",
				},
			},
			expected:    false,
			description: "no annotation should fall back to default=false",
		},
		{
			name: "empty annotations map with default true",
			config: Config{
				EnableDefaultGlobalNamespace: true,
			},
			namespace: &slim_corev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:        "test-ns",
					Annotations: map[string]string{},
				},
			},
			expected:    true,
			description: "empty annotations should fall back to default",
		},
		{
			name: "annotation with invalid value",
			config: Config{
				EnableDefaultGlobalNamespace: true,
			},
			namespace: &slim_corev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "test-ns",
					Annotations: map[string]string{
						annotation.GlobalNamespace: "invalid",
					},
				},
			},
			expected:    false,
			description: "invalid annotation value should be treated as false",
		},
		{
			name: "annotation empty string with default true",
			config: Config{
				EnableDefaultGlobalNamespace: true,
			},
			namespace: &slim_corev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "test-ns",
					Annotations: map[string]string{
						annotation.GlobalNamespace: "",
					},
				},
			},
			expected:    false,
			description: "empty annotation value should be treated as false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &manager{
				logger: slog.Default(),
				cfg:    tt.config,
			}
			result := m.IsGlobalNamespaceByObject(tt.namespace)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestIsGlobalNamespaceByName(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		nsName      string
		namespaces  []*slim_corev1.Namespace
		expectError bool
		expected    bool
		description string
	}{
		{
			name: "namespace exists with annotation true",
			config: Config{
				EnableDefaultGlobalNamespace: false,
			},
			nsName: "global-ns",
			namespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "global-ns",
						Annotations: map[string]string{
							annotation.GlobalNamespace: "true",
						},
					},
				},
			},
			expectError: false,
			expected:    true,
			description: "should return true for annotated global namespace",
		},
		{
			name: "namespace exists with annotation false",
			config: Config{
				EnableDefaultGlobalNamespace: true,
			},
			nsName: "local-ns",
			namespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "local-ns",
						Annotations: map[string]string{
							annotation.GlobalNamespace: "false",
						},
					},
				},
			},
			expectError: false,
			expected:    false,
			description: "should return false for annotated local namespace",
		},
		{
			name: "namespace does not exist",
			config: Config{
				EnableDefaultGlobalNamespace: true,
			},
			nsName: "non-existent",
			namespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "other-ns",
					},
				},
			},
			expectError: true,
			expected:    false,
			description: "should return error when namespace doesn't exist",
		},
		{
			name: "multiple namespaces, find correct one",
			config: Config{
				EnableDefaultGlobalNamespace: false,
			},
			nsName: "target-ns",
			namespaces: []*slim_corev1.Namespace{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "ns1",
						Annotations: map[string]string{
							annotation.GlobalNamespace: "false",
						},
					},
				},
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "target-ns",
						Annotations: map[string]string{
							annotation.GlobalNamespace: "true",
						},
					},
				},
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name: "ns3",
					},
				},
			},
			expectError: false,
			expected:    true,
			description: "should find and evaluate correct namespace from multiple",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock namespace store
			store := NewMockNamespaceStore(tt.namespaces...)

			m := &manager{
				logger: slog.Default(),
				cfg:    tt.config,
				store:  store,
			}

			result, err := m.IsGlobalNamespaceByName(tt.nsName)

			if tt.expectError {
				require.Error(t, err, tt.description)
			} else {
				require.NoError(t, err, tt.description)
				assert.Equal(t, tt.expected, result, tt.description)
			}
		})
	}
}
