package clustermesh

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
)

func TestGlobalNamespaceFilter(t *testing.T) {
	// Test the backwards compatibility case - no namespaces annotated, all should be global
	tracker := &namespaceWatcher{
		config:          NamespaceWatcherConfig{DefaultGlobalNamespace: true},
		global:          sets.New[string](),
		annotated:       sets.New[string](),
		filteringActive: false, // No namespaces annotated
	}

	filter := NewGlobalNamespaceFilter(tracker)

	if !filter.ShouldExport("any-namespace") {
		t.Error("when no namespaces are annotated, should export from any namespace")
	}

	// Test the annotation-based filter with default=true
	tracker2 := &namespaceWatcher{
		config:          NamespaceWatcherConfig{DefaultGlobalNamespace: true},
		global:          sets.New("global-ns"),
		annotated:       sets.New("global-ns", "local-ns"), // Both namespaces are annotated
		filteringActive: true,
	}

	filter2 := NewGlobalNamespaceFilter(tracker2)

	if !filter2.ShouldExport("global-ns") {
		t.Error("filter should export from explicitly global namespace")
	}

	if filter2.ShouldExport("local-ns") {
		t.Error("filter should not export from explicitly local namespace")
	}

	if !filter2.ShouldExport("unannotated-ns") {
		t.Error("filter should export from unannotated namespace when default is global")
	}

	// Test with default=false
	tracker3 := &namespaceWatcher{
		config:          NamespaceWatcherConfig{DefaultGlobalNamespace: false},
		global:          sets.New("global-ns"),
		annotated:       sets.New("global-ns", "local-ns"),
		filteringActive: true,
	}

	filter3 := NewGlobalNamespaceFilter(tracker3)

	if !filter3.ShouldExport("global-ns") {
		t.Error("filter should export from explicitly global namespace")
	}

	if filter3.ShouldExport("local-ns") {
		t.Error("filter should not export from explicitly local namespace")
	}

	if filter3.ShouldExport("unannotated-ns") {
		t.Error("filter should not export from unannotated namespace when default is local")
	}
}

func TestNamespaceWatcherConfig(t *testing.T) {
	// Test backwards compatibility - no annotations, all namespaces global
	watcher := NewNamespaceWatcher(nil, NamespaceWatcherConfig{DefaultGlobalNamespace: true})

	if !watcher.IsGlobalNamespace("any-namespace") {
		t.Error("when no namespaces are annotated, any namespace should be global")
	}

	globalSet := watcher.GetGlobalNamespaces()
	if globalSet.Len() != 0 {
		t.Error("when no namespaces are annotated, GetGlobalNamespaces should return empty set indicating all are global")
	}

	// Test filtering active with default=true
	watcher2 := NewNamespaceWatcher(nil, NamespaceWatcherConfig{DefaultGlobalNamespace: true})
	// Simulate filtering becoming active by adding an annotated namespace
	watcher2.annotated.Insert("annotated-ns")
	watcher2.global.Insert("annotated-ns") // annotated as global
	watcher2.filteringActive = true

	if !watcher2.IsGlobalNamespace("annotated-ns") {
		t.Error("annotated-ns should be global when explicitly marked as global")
	}

	if !watcher2.IsGlobalNamespace("unannotated-ns") {
		t.Error("unannotated-ns should be global when default is true")
	}

	// Test filtering active with default=false
	watcher3 := NewNamespaceWatcher(nil, NamespaceWatcherConfig{DefaultGlobalNamespace: false})
	watcher3.annotated.Insert("annotated-ns")
	watcher3.global.Insert("annotated-ns") // annotated as global
	watcher3.filteringActive = true

	if !watcher3.IsGlobalNamespace("annotated-ns") {
		t.Error("annotated-ns should be global when explicitly marked as global")
	}

	if watcher3.IsGlobalNamespace("unannotated-ns") {
		t.Error("unannotated-ns should not be global when default is false")
	}
}
