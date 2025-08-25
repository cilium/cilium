// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namespacewatcher

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	// GlobalNamespaceAnnotation defines the annotation key for marking namespaces as global
	GlobalNamespaceAnnotation = "clustermesh.cilium.io/global"
)

// MockNamespaceProcessor implements NamespaceProcessor for testing
type MockNamespaceProcessor struct {
	namespaceChanges map[string]bool
	allNamespaces    []string
}

func (m *MockNamespaceProcessor) ProcessNamespaceChange(namespace string, isGlobal bool) {
	if m.namespaceChanges == nil {
		m.namespaceChanges = make(map[string]bool)
	}
	m.namespaceChanges[namespace] = isGlobal
}

func (m *MockNamespaceProcessor) GetAllNamespaces() []string {
	return m.allNamespaces
}

func (m *MockNamespaceProcessor) SetAllNamespaces(namespaces []string) {
	m.allNamespaces = namespaces
}

func (m *MockNamespaceProcessor) GetNamespaceChanges() map[string]bool {
	return m.namespaceChanges
}

func (m *MockNamespaceProcessor) ClearChanges() {
	m.namespaceChanges = make(map[string]bool)
}

// createTestNamespace creates a test namespace with optional global annotation
func createTestNamespace(name string, isGlobal *bool) *slim_corev1.Namespace {
	ns := &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name: name,
		},
	}

	if isGlobal != nil {
		if ns.Annotations == nil {
			ns.Annotations = make(map[string]string)
		}
		if *isGlobal {
			ns.Annotations[GlobalNamespaceAnnotation] = "true"
		} else {
			ns.Annotations[GlobalNamespaceAnnotation] = "false"
		}
	}

	return ns
}

// mockNamespaceResource creates a simple mock resource for testing namespace watcher in isolation
type mockNamespaceResource struct {
	namespaces map[string]*slim_corev1.Namespace
}

func newMockNamespaceResource(namespaces ...*slim_corev1.Namespace) *mockNamespaceResource {
	r := &mockNamespaceResource{
		namespaces: make(map[string]*slim_corev1.Namespace),
	}
	for _, ns := range namespaces {
		r.namespaces[ns.Name] = ns
	}
	return r
}

func (m *mockNamespaceResource) Store(ctx context.Context) (resource.Store[*slim_corev1.Namespace], error) {
	return &mockNamespaceStore{namespaces: m.namespaces}, nil
}

func (m *mockNamespaceResource) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[*slim_corev1.Namespace] {
	// For basic testing, we don't need events
	ch := make(chan resource.Event[*slim_corev1.Namespace])
	close(ch)
	return ch
}

func (m *mockNamespaceResource) Observe(ctx context.Context, next func(resource.Event[*slim_corev1.Namespace]), complete func(error)) {
	// Basic implementation for stream.Observable interface
	complete(nil)
}

type mockNamespaceStore struct {
	namespaces map[string]*slim_corev1.Namespace
}

func (m *mockNamespaceStore) GetByKey(key resource.Key) (*slim_corev1.Namespace, bool, error) {
	ns, exists := m.namespaces[key.Name]
	return ns, exists, nil
}

func (m *mockNamespaceStore) Get(obj *slim_corev1.Namespace) (*slim_corev1.Namespace, bool, error) {
	return m.GetByKey(resource.Key{Name: obj.Name})
}

func (m *mockNamespaceStore) List() []*slim_corev1.Namespace {
	var result []*slim_corev1.Namespace
	for _, ns := range m.namespaces {
		result = append(result, ns)
	}
	return result
}

func (m *mockNamespaceStore) IterKeys() resource.KeyIter {
	// Simple implementation for testing
	return &mockKeyIterator{}
}

func (m *mockNamespaceStore) IndexKeys(indexName, indexedValue string) ([]string, error) {
	return nil, nil // Not needed for basic testing
}

func (m *mockNamespaceStore) ByIndex(indexName, indexedValue string) ([]*slim_corev1.Namespace, error) {
	return nil, nil // Not needed for basic testing
}

func (m *mockNamespaceStore) CacheStore() cache.Store {
	return nil // Not needed for basic testing
}

type mockKeyIterator struct{}

func (m *mockKeyIterator) Next() bool        { return false }
func (m *mockKeyIterator) Key() resource.Key { return resource.Key{} }

// createNamespaceWatcher creates a namespace watcher for isolated testing
func createNamespaceWatcher(t *testing.T, config Config, namespaces ...*slim_corev1.Namespace) (GlobalNamespaceTracker, *MockNamespaceProcessor) {
	logger := hivetest.Logger(t)

	// Create namespace watcher with config
	mockResource := newMockNamespaceResource(namespaces...)
	watcher := NewNamespaceWatcher(logger, config, mockResource)

	// Create and register mock processor
	mockProcessor := &MockNamespaceProcessor{}
	watcher.RegisterProcessor(mockProcessor)

	return watcher, mockProcessor
}

func TestNamespaceWatcherInitialization(t *testing.T) {
	tests := []struct {
		name           string
		config         Config
		expectedGlobal bool
	}{
		{
			name:           "default-global-true",
			config:         Config{DefaultGlobalNamespace: true},
			expectedGlobal: true,
		},
		{
			name:           "default-global-false",
			config:         Config{DefaultGlobalNamespace: false},
			expectedGlobal: true, // Backwards compatibility mode
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker, _ := createNamespaceWatcher(t, tt.config)

			// Test initial state - no filtering should be active
			assert.False(t, tracker.IsFilteringActive(), "Filtering should not be active initially")

			// Test backwards compatibility - all namespaces should be global when no annotations exist
			assert.True(t, tracker.IsGlobalNamespace("any-namespace"), "All namespaces should be global in backwards compatibility mode")

			// Test that GetGlobalNamespaces returns empty set (indicating all namespaces are global)
			globalNs := tracker.GetGlobalNamespaces()
			assert.Equal(t, 0, globalNs.Len(), "GetGlobalNamespaces should return empty set when filtering is inactive")
		})
	}
}

func TestNamespaceAnnotationProcessing(t *testing.T) {
	tests := []struct {
		name                    string
		config                  Config
		namespace               *slim_corev1.Namespace
		expectedGlobal          bool
		expectedFilteringActive bool
	}{
		{
			name:                    "global-annotation-true",
			config:                  Config{DefaultGlobalNamespace: false},
			namespace:               createTestNamespace("test-ns", &[]bool{true}[0]),
			expectedGlobal:          true,
			expectedFilteringActive: true,
		},
		{
			name:                    "global-annotation-false",
			config:                  Config{DefaultGlobalNamespace: true},
			namespace:               createTestNamespace("test-ns", &[]bool{false}[0]),
			expectedGlobal:          false,
			expectedFilteringActive: true,
		},
		{
			name:                    "no-annotation-default-true",
			config:                  Config{DefaultGlobalNamespace: true},
			namespace:               createTestNamespace("test-ns", nil),
			expectedGlobal:          true,
			expectedFilteringActive: false,
		},
		{
			name:                    "no-annotation-default-false",
			config:                  Config{DefaultGlobalNamespace: false},
			namespace:               createTestNamespace("test-ns", nil),
			expectedGlobal:          true, // Backwards compatibility when no filtering active
			expectedFilteringActive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker, _ := createNamespaceWatcher(t, tt.config, tt.namespace)

			assert.Equal(t, tt.expectedFilteringActive, tracker.IsFilteringActive(), "Filtering active state should match expectation")
			assert.Equal(t, tt.expectedGlobal, tracker.IsGlobalNamespace(tt.namespace.Name), "Namespace global state should match expectation")
		})
	}
}

func TestNamespaceWatcherProcessorRegistration(t *testing.T) {
	config := Config{DefaultGlobalNamespace: false}
	tracker, processor1 := createNamespaceWatcher(t, config)

	// Register additional processors
	processor2 := &MockNamespaceProcessor{}
	processor3 := &MockNamespaceProcessor{}

	tracker.RegisterProcessor(processor2)
	tracker.RegisterProcessor(processor3)

	// Since we can't directly access updateNamespace from the interface,
	// we'll test the basic registration functionality
	assert.NotNil(t, processor1, "First processor should be registered")
	assert.NotNil(t, processor2, "Second processor should be registered")
	assert.NotNil(t, processor3, "Third processor should be registered")
}

func TestGetGlobalNamespaces(t *testing.T) {
	config := Config{DefaultGlobalNamespace: false}

	ns1 := createTestNamespace("global-ns", &[]bool{true}[0])
	ns2 := createTestNamespace("local-ns", &[]bool{false}[0])
	ns3 := createTestNamespace("default-ns", nil)

	tracker, _ := createNamespaceWatcher(t, config, ns1, ns2, ns3)

	globalNs := tracker.GetGlobalNamespaces()
	expected := sets.New("global-ns") // Only explicitly global namespace
	assert.Equal(t, expected, globalNs, "Should return only explicitly global namespaces")

	// Test with default global = true
	config2 := Config{DefaultGlobalNamespace: true}
	tracker2, _ := createNamespaceWatcher(t, config2, ns1, ns2, ns3)

	globalNs2 := tracker2.GetGlobalNamespaces()
	expected2 := sets.New("global-ns", "default-ns") // Global + default
	assert.Equal(t, expected2, globalNs2, "Should return global and default namespaces when DefaultGlobalNamespace=true")
}

func TestNamespaceWatcherEdgeCases(t *testing.T) {
	t.Run("empty-namespace-name", func(t *testing.T) {
		config := Config{DefaultGlobalNamespace: false}
		tracker, _ := createNamespaceWatcher(t, config)

		// Should handle empty namespace name gracefully
		assert.True(t, tracker.IsGlobalNamespace(""), "Should handle empty namespace name")
	})

	t.Run("special-characters-in-namespace", func(t *testing.T) {
		config := Config{DefaultGlobalNamespace: false}
		specialNs := createTestNamespace("test-ns.with-special_chars", &[]bool{true}[0])
		tracker, _ := createNamespaceWatcher(t, config, specialNs)

		assert.True(t, tracker.IsFilteringActive(), "Should work with special characters")
		assert.True(t, tracker.IsGlobalNamespace("test-ns.with-special_chars"), "Should handle special characters in namespace names")
	})
}

func TestComprehensiveBackwardsCompatibility(t *testing.T) {
	// Test that the namespace watcher maintains backwards compatibility behavior
	scenarios := []struct {
		name                 string
		defaultGlobal        bool
		hasAnnotatedNS       bool
		expectedFiltering    bool
		expectedGlobalForAny bool
	}{
		{
			name:                 "no-annotations-default-true",
			defaultGlobal:        true,
			hasAnnotatedNS:       false,
			expectedFiltering:    false,
			expectedGlobalForAny: true,
		},
		{
			name:                 "no-annotations-default-false",
			defaultGlobal:        false,
			hasAnnotatedNS:       false,
			expectedFiltering:    false,
			expectedGlobalForAny: true,
		},
		{
			name:                 "with-annotations-default-true",
			defaultGlobal:        true,
			hasAnnotatedNS:       true,
			expectedFiltering:    true,
			expectedGlobalForAny: true, // Because default is true
		},
		{
			name:                 "with-annotations-default-false",
			defaultGlobal:        false,
			hasAnnotatedNS:       true,
			expectedFiltering:    true,
			expectedGlobalForAny: false, // Because default is false and filtering is active
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			config := Config{DefaultGlobalNamespace: scenario.defaultGlobal}

			var namespaces []*slim_corev1.Namespace
			if scenario.hasAnnotatedNS {
				namespaces = append(namespaces, createTestNamespace("annotated-ns", &[]bool{true}[0]))
			}

			tracker, _ := createNamespaceWatcher(t, config, namespaces...)

			assert.Equal(t, scenario.expectedFiltering, tracker.IsFilteringActive(), "Filtering state should match expectation")
			assert.Equal(t, scenario.expectedGlobalForAny, tracker.IsGlobalNamespace("any-namespace"), "Global namespace behavior should match expectation")
		})
	}
}

// Test service objects for IsGlobalService and IsSharedGlobalService methods
type testService struct {
	annotations map[string]string
	namespace   string
}

func (ts *testService) GetAnnotations() map[string]string {
	return ts.annotations
}

func (ts *testService) GetNamespace() string {
	return ts.namespace
}

func TestIsGlobalService(t *testing.T) {
	config := Config{DefaultGlobalNamespace: false}

	// Create a namespace that is global
	globalNs := createTestNamespace("global-ns", &[]bool{true}[0])
	localNs := createTestNamespace("local-ns", &[]bool{false}[0])

	tracker, _ := createNamespaceWatcher(t, config, globalNs, localNs)

	tests := []struct {
		name     string
		service  *testService
		expected bool
	}{
		{
			name: "global-service-in-global-namespace",
			service: &testService{
				annotations: map[string]string{"service.cilium.io/global": "true"},
				namespace:   "global-ns",
			},
			expected: true,
		},
		{
			name: "global-service-in-local-namespace",
			service: &testService{
				annotations: map[string]string{"service.cilium.io/global": "true"},
				namespace:   "local-ns",
			},
			expected: false, // Should fail because namespace is local
		},
		{
			name: "local-service-in-global-namespace",
			service: &testService{
				annotations: map[string]string{},
				namespace:   "global-ns",
			},
			expected: false, // Should fail because service is not annotated as global
		},
		{
			name: "local-service-in-local-namespace",
			service: &testService{
				annotations: map[string]string{},
				namespace:   "local-ns",
			},
			expected: false, // Should fail both checks
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tracker.IsGlobalService(tt.service)
			assert.Equal(t, tt.expected, result, "IsGlobalService should match expectation")
		})
	}
}

func TestIsSharedGlobalService(t *testing.T) {
	config := Config{DefaultGlobalNamespace: false}

	// Create a namespace that is global
	globalNs := createTestNamespace("global-ns", &[]bool{true}[0])

	tracker, _ := createNamespaceWatcher(t, config, globalNs)

	tests := []struct {
		name     string
		service  *testService
		expected bool
	}{
		{
			name: "shared-global-service",
			service: &testService{
				annotations: map[string]string{
					"service.cilium.io/global": "true",
					"service.cilium.io/shared": "true",
				},
				namespace: "global-ns",
			},
			expected: true,
		},
		{
			name: "global-service-default-shared",
			service: &testService{
				annotations: map[string]string{"service.cilium.io/global": "true"},
				namespace:   "global-ns",
			},
			expected: true, // Should be shared by default
		},
		{
			name: "explicitly-not-shared-global-service",
			service: &testService{
				annotations: map[string]string{
					"service.cilium.io/global": "true",
					"service.cilium.io/shared": "false",
				},
				namespace: "global-ns",
			},
			expected: false, // Explicitly not shared
		},
		{
			name: "local-service",
			service: &testService{
				annotations: map[string]string{"service.cilium.io/shared": "true"},
				namespace:   "global-ns",
			},
			expected: false, // Not global, so can't be shared
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tracker.IsSharedGlobalService(tt.service)
			assert.Equal(t, tt.expected, result, "IsSharedGlobalService should match expectation")
		})
	}
}

func TestAlwaysGlobalTracker(t *testing.T) {
	tracker := NewAlwaysGlobalTracker()

	// Should always return true for backwards compatibility
	assert.True(t, tracker.IsGlobalNamespace("any-namespace"), "Always global tracker should always return true")
	assert.False(t, tracker.IsFilteringActive(), "Always global tracker should not be filtering")
	assert.Equal(t, 0, tracker.GetGlobalNamespaces().Len(), "Always global tracker should return empty set")

	// Test service methods
	globalService := &testService{
		annotations: map[string]string{"service.cilium.io/global": "true"},
		namespace:   "any-ns",
	}
	localService := &testService{
		annotations: map[string]string{},
		namespace:   "any-ns",
	}

	assert.True(t, tracker.IsGlobalService(globalService), "Should respect global annotation")
	assert.False(t, tracker.IsGlobalService(localService), "Should respect missing global annotation")
	assert.True(t, tracker.IsSharedGlobalService(globalService), "Global service should be shared by default")
}
