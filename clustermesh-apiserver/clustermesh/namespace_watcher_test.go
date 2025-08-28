package clustermesh

import (
	"testing"
)

func TestGlobalNamespaceFilter(t *testing.T) {
	// Test with filtering active - only explicitly marked namespaces should be global
	tracker := newMockGlobalNamespaceTracker()
	tracker.setNamespaceGlobal("global-ns", true)

	filter := NewGlobalNamespaceFilter(tracker)

	if !filter.ShouldExport("global-ns") {
		t.Error("filter should export from explicitly global namespace")
	}

	if filter.ShouldExport("any-namespace") {
		t.Error("filter should not export from non-global namespace when filtering is active")
	}

	// Test removing global status
	tracker2 := newMockGlobalNamespaceTracker()
	tracker2.setNamespaceGlobal("local-ns", false)

	filter2 := NewGlobalNamespaceFilter(tracker2)

	if filter2.ShouldExport("local-ns") {
		t.Error("filter should not export from explicitly local namespace")
	}
}

func TestNamespaceWatcherConfig(t *testing.T) {
	// Test basic functionality with mock tracker
	tracker := newMockGlobalNamespaceTracker()

	if tracker.IsFilteringActive() {
		t.Error("initially, filtering should not be active")
	}

	globalSet := tracker.GetGlobalNamespaces()
	if globalSet.Len() != 0 {
		t.Error("initially, GetGlobalNamespaces should return empty set")
	}

	// Test activating filtering
	tracker.setNamespaceGlobal("annotated-ns", true)

	if !tracker.IsFilteringActive() {
		t.Error("filtering should be active after adding first annotation")
	}

	if !tracker.IsGlobalNamespace("annotated-ns") {
		t.Error("annotated-ns should be global when explicitly marked as global")
	}

	// Test deactivating filtering
	tracker.setNamespaceGlobal("annotated-ns", false)

	if tracker.IsFilteringActive() {
		t.Error("filtering should be inactive after removing all annotations")
	}
}
