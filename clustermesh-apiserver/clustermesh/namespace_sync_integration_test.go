// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/clustermesh"
)

// TestNamespaceSyncCallback tests that namespace change processors trigger the correct behavior
func TestNamespaceSyncCallback(t *testing.T) {
	// Create a mock namespace tracker
	tracker := newMockGlobalNamespaceTracker()

	// Track processor invocations
	processorInvocations := []struct {
		namespace string
		isGlobal  bool
	}{}

	// Create a test processor
	testProcessor := &testNamespaceProcessor{
		callback: func(namespace string, isGlobal bool) {
			processorInvocations = append(processorInvocations, struct {
				namespace string
				isGlobal  bool
			}{namespace, isGlobal})
		},
		namespaces: []string{"production", "development"}, // Simulate known namespaces
	}

	// Register the processor
	tracker.RegisterProcessor(testProcessor)

	// Initially no namespaces are global
	assert.False(t, tracker.IsGlobalNamespace("production"))
	assert.False(t, tracker.IsGlobalNamespace("development"))

	// Make production namespace global
	tracker.setNamespaceGlobal("production", true)

	// Verify processor was triggered
	assert.Len(t, processorInvocations, 1)
	assert.Equal(t, "production", processorInvocations[0].namespace)
	assert.True(t, processorInvocations[0].isGlobal)

	// Verify namespace is now global
	assert.True(t, tracker.IsGlobalNamespace("production"))
	assert.False(t, tracker.IsGlobalNamespace("development"))

	// Make development namespace global
	tracker.setNamespaceGlobal("development", true)

	// Verify second processor was triggered
	assert.Len(t, processorInvocations, 2)
	assert.Equal(t, "development", processorInvocations[1].namespace)
	assert.True(t, processorInvocations[1].isGlobal)

	// Both namespaces should now be global
	assert.True(t, tracker.IsGlobalNamespace("production"))
	assert.True(t, tracker.IsGlobalNamespace("development"))

	// Remove global status from production
	tracker.setNamespaceGlobal("production", false)

	// Verify third processor was triggered
	assert.Len(t, processorInvocations, 3)
	assert.Equal(t, "production", processorInvocations[2].namespace)
	assert.False(t, processorInvocations[2].isGlobal)

	// Only development should be global now
	assert.False(t, tracker.IsGlobalNamespace("production"))
	assert.True(t, tracker.IsGlobalNamespace("development"))
}

// TestNamespaceFilterIntegration tests the integration between namespace tracker and filter
func TestNamespaceFilterIntegration(t *testing.T) {
	// Create a mock namespace tracker
	tracker := newMockGlobalNamespaceTracker()

	// Create a namespace filter using the tracker
	filter := NewGlobalNamespaceFilter(tracker)

	// Initially no namespaces are global
	assert.False(t, filter.ShouldExport("production"))
	assert.False(t, filter.ShouldExport("development"))

	// Make production namespace global
	tracker.setNamespaceGlobal("production", true)

	// Now production should be exportable but not development
	assert.True(t, filter.ShouldExport("production"))
	assert.False(t, filter.ShouldExport("development"))

	// Make development global too
	tracker.setNamespaceGlobal("development", true)

	// Both should be exportable
	assert.True(t, filter.ShouldExport("production"))
	assert.True(t, filter.ShouldExport("development"))

	// Remove global status from production
	tracker.setNamespaceGlobal("production", false)

	// Only development should be exportable
	assert.False(t, filter.ShouldExport("production"))
	assert.True(t, filter.ShouldExport("development"))
}

// mockGlobalNamespaceTracker is a simple mock implementation for testing
type mockGlobalNamespaceTracker struct {
	globalNamespaces sets.Set[string]
	processors       []clustermesh.NamespaceProcessor
}

func newMockGlobalNamespaceTracker() *mockGlobalNamespaceTracker {
	return &mockGlobalNamespaceTracker{
		globalNamespaces: sets.New[string](),
		processors:       []clustermesh.NamespaceProcessor{},
	}
}

func (m *mockGlobalNamespaceTracker) IsGlobalNamespace(namespace string) bool {
	return m.globalNamespaces.Has(namespace)
}

func (m *mockGlobalNamespaceTracker) GetGlobalNamespaces() sets.Set[string] {
	return m.globalNamespaces.Clone()
}

func (m *mockGlobalNamespaceTracker) IsFilteringActive() bool {
	return m.globalNamespaces.Len() > 0
}

func (m *mockGlobalNamespaceTracker) RegisterProcessor(processor clustermesh.NamespaceProcessor) {
	m.processors = append(m.processors, processor)
}

func (m *mockGlobalNamespaceTracker) setNamespaceGlobal(namespace string, isGlobal bool) {
	wasGlobal := m.globalNamespaces.Has(namespace)

	if isGlobal {
		m.globalNamespaces.Insert(namespace)
	} else {
		m.globalNamespaces.Delete(namespace)
	}

	// Only trigger processors if status actually changed
	if wasGlobal != isGlobal {
		for _, processor := range m.processors {
			processor.ProcessNamespaceChange(namespace, isGlobal)
		}
	}
}

// testNamespaceProcessor is a simple test implementation of NamespaceProcessor
type testNamespaceProcessor struct {
	callback   func(namespace string, isGlobal bool)
	namespaces []string // Namespaces this processor knows about
}

func (p *testNamespaceProcessor) ProcessNamespaceChange(namespace string, isGlobal bool) {
	if p.callback != nil {
		p.callback(namespace, isGlobal)
	}
}

func (p *testNamespaceProcessor) GetAllNamespaces() []string {
	return p.namespaces
}
