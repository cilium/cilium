// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namespace

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// NewMockNamespaceManager creates a Namespace Manager with a fake clientset and the provided namespaces.
func NewMockNamespaceManager(t *testing.T, enableDefaultGlobalNamespace bool, namespaces ...*slim_corev1.Namespace) Manager {
	var (
		log             = hivetest.Logger(t)
		lc              = hivetest.Lifecycle(t)
		cs, _           = k8sFakeClient.NewFakeClientset(log)
		namespaceRes, _ = k8s.NamespaceResource(lc, cs, nil)
	)
	for _, ns := range namespaces {
		_, err := cs.Slim().CoreV1().Namespaces().Create(t.Context(), ns, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	return newManager(managerParams{
		Logger:     log,
		Lifecycle:  lc,
		Namespaces: namespaceRes,
		Config: Config{
			GlobalNamespacesByDefault: enableDefaultGlobalNamespace,
		},
	})
}

func TestIsGlobalNamespace(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		namespace   *slim_corev1.Namespace
		expected    bool
		expectError bool
		description string
	}{
		{
			name: "nil namespace",
			config: Config{
				GlobalNamespacesByDefault: true,
			},
			namespace:   nil,
			expected:    false,
			description: "nil namespace should always return false",
		},
		{
			name: "annotation true with default false",
			config: Config{
				GlobalNamespacesByDefault: false,
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
				GlobalNamespacesByDefault: true,
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
				GlobalNamespacesByDefault: false,
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
				GlobalNamespacesByDefault: false,
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
				GlobalNamespacesByDefault: true,
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
				GlobalNamespacesByDefault: false,
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
				GlobalNamespacesByDefault: true,
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
				GlobalNamespacesByDefault: true,
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
				GlobalNamespacesByDefault: true,
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
		{
			name: "annotation true with default true",
			config: Config{
				GlobalNamespacesByDefault: true,
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
			description: "annotation=true with default=true should return true",
		},
		{
			name: "annotation false with default false",
			config: Config{
				GlobalNamespacesByDefault: false,
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
			description: "annotation=false with default=false should return false",
		},
		{
			name: "namespace does not exist",
			config: Config{
				GlobalNamespacesByDefault: true,
			},
			namespace: &slim_corev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name: "non-existent",
				},
			},
			expected:    false,
			expectError: true,
			description: "should return error when namespace doesn't exist",
		},
	}

	t.Run("ByObject", func(t *testing.T) {
		for _, tt := range tests {
			// Skip error scenarios for ByObject
			if tt.expectError {
				continue
			}

			t.Run(tt.name, func(t *testing.T) {
				var m Manager
				if tt.namespace != nil {
					m = NewMockNamespaceManager(t, tt.config.GlobalNamespacesByDefault, tt.namespace)
				} else {
					m = NewMockNamespaceManager(t, tt.config.GlobalNamespacesByDefault)
				}

				result := m.IsGlobalNamespaceByObject(tt.namespace)
				assert.Equal(t, tt.expected, result, tt.description)
			})
		}
	})

	t.Run("ByName", func(t *testing.T) {
		for _, tt := range tests {
			// Skip nil namespace test for ByName
			if tt.namespace == nil {
				continue
			}

			t.Run(tt.name, func(t *testing.T) {
				// For error scenarios, don't create the namespace
				var m Manager
				if tt.expectError {
					m = NewMockNamespaceManager(t, tt.config.GlobalNamespacesByDefault)
				} else {
					m = NewMockNamespaceManager(t, tt.config.GlobalNamespacesByDefault, tt.namespace)
				}

				result, err := m.IsGlobalNamespaceByName(tt.namespace.Name)
				if tt.expectError {
					require.Error(t, err, tt.description)
				} else {
					require.NoError(t, err, "should not error for existing namespace")
					assert.Equal(t, tt.expected, result, tt.description)
				}
			})
		}
	})
}
