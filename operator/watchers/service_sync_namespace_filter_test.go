// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// mockNamespaceTracker implements GlobalNamespaceTracker for testing
type mockNamespaceTracker struct {
	filteringActive  bool
	globalNamespaces map[string]bool
}

func (m *mockNamespaceTracker) IsGlobalNamespace(namespace string) bool {
	return m.globalNamespaces[namespace]
}

func (m *mockNamespaceTracker) GetGlobalNamespaces() sets.Set[string] {
	result := sets.New[string]()
	for ns := range m.globalNamespaces {
		if m.globalNamespaces[ns] {
			result.Insert(ns)
		}
	}
	return result
}

func (m *mockNamespaceTracker) RegisterProcessor(processor clustermesh.NamespaceProcessor) {
	// Not needed for this test
}

func (m *mockNamespaceTracker) IsFilteringActive() bool {
	return m.filteringActive
}

func TestGlobalServiceDualRequirements(t *testing.T) {
	tests := []struct {
		name              string
		serviceAnnotation string
		serviceName       string
		serviceNamespace  string
		filteringActive   bool
		namespaceGlobal   bool
		expectedShared    bool
		description       string
	}{
		{
			name:              "global-service-in-global-namespace",
			serviceAnnotation: "true",
			serviceName:       "test-service",
			serviceNamespace:  "global-ns",
			filteringActive:   true,
			namespaceGlobal:   true,
			expectedShared:    true,
			description:       "Service with global annotation in global namespace should be shared",
		},
		{
			name:              "global-service-in-local-namespace",
			serviceAnnotation: "true",
			serviceName:       "test-service",
			serviceNamespace:  "local-ns",
			filteringActive:   true,
			namespaceGlobal:   false,
			expectedShared:    false,
			description:       "Service with global annotation in local namespace should NOT be shared",
		},
		{
			name:              "local-service-in-global-namespace",
			serviceAnnotation: "false",
			serviceName:       "test-service",
			serviceNamespace:  "global-ns",
			filteringActive:   true,
			namespaceGlobal:   true,
			expectedShared:    false,
			description:       "Service without global annotation should NOT be shared regardless of namespace",
		},
		{
			name:              "local-service-in-local-namespace",
			serviceAnnotation: "false",
			serviceName:       "test-service",
			serviceNamespace:  "local-ns",
			filteringActive:   true,
			namespaceGlobal:   false,
			expectedShared:    false,
			description:       "Service without global annotation in local namespace should NOT be shared",
		},
		{
			name:              "global-service-no-filtering",
			serviceAnnotation: "true",
			serviceName:       "test-service",
			serviceNamespace:  "any-ns",
			filteringActive:   false,
			namespaceGlobal:   false,
			expectedShared:    true,
			description:       "When filtering is inactive, only service annotation matters (backwards compatibility)",
		},
		{
			name:              "no-annotation-service",
			serviceAnnotation: "",
			serviceName:       "test-service",
			serviceNamespace:  "global-ns",
			filteringActive:   true,
			namespaceGlobal:   true,
			expectedShared:    false,
			description:       "Service without global annotation should NOT be shared",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock namespace tracker
			tracker := &mockNamespaceTracker{
				filteringActive: tt.filteringActive,
				globalNamespaces: map[string]bool{
					tt.serviceNamespace: tt.namespaceGlobal,
				},
			}

			// Create test service
			service := &slim_corev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:        tt.serviceName,
					Namespace:   tt.serviceNamespace,
					Annotations: map[string]string{},
				},
				Spec: slim_corev1.ServiceSpec{
					ClusterIP: "10.0.0.1",
					Ports: []slim_corev1.ServicePort{
						{
							Name: "http",
							Port: 80,
						},
					},
				},
			}

			// Set global service annotation if provided
			if tt.serviceAnnotation != "" {
				service.Annotations["service.cilium.io/global"] = tt.serviceAnnotation
			}

			// Create converter with namespace tracker
			converter := DefaultClusterServiceConverter{
				cinfo: cmtypes.ClusterInfo{
					Name: "test-cluster",
					ID:   1,
				},
				namespaceTracker: tracker,
			}

			// Test the Convert method
			_, shouldUpsert := converter.Convert(service, func(namespace, name string) []*k8s.Endpoints {
				return nil
			})

			// Verify the result matches the expected behavior per CFP-39876
			assert.Equal(t, tt.expectedShared, shouldUpsert, tt.description)
		})
	}
}
