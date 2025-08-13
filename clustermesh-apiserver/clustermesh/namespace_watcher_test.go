package clustermesh

import (
	"fmt"
	"io"
	"log/slog"
	"testing"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
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
	// Create a no-op logger to avoid nil pointer panics
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Test backwards compatibility - no annotations, all namespaces global
	watcher := NewNamespaceWatcher(logger, NamespaceWatcherConfig{DefaultGlobalNamespace: true})

	if !watcher.IsGlobalNamespace("any-namespace") {
		t.Error("when no namespaces are annotated, any namespace should be global")
	}

	globalSet := watcher.GetGlobalNamespaces()
	if globalSet.Len() != 0 {
		t.Error("when no namespaces are annotated, GetGlobalNamespaces should return empty set indicating all are global")
	}

	// Test filtering active with default=true
	watcher2 := NewNamespaceWatcher(logger, NamespaceWatcherConfig{DefaultGlobalNamespace: true})
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
	watcher3 := NewNamespaceWatcher(logger, NamespaceWatcherConfig{DefaultGlobalNamespace: false})
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

func TestNamespaceWatcherBackfillEdgeCase(t *testing.T) {
	// Test the edge case: when the last annotated namespace is unannotated,
	// all namespaces should become global again (revert to old behavior)

	// Create a mock processor to track calls
	calls := make([]string, 0)
	processor := &mockProcessor{calls: &calls}

	// Create a no-op logger to avoid nil pointer panics
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	watcher := NewNamespaceWatcher(logger, NamespaceWatcherConfig{DefaultGlobalNamespace: false})
	watcher.syncProcessing = true // Enable synchronous processing for testing
	watcher.RegisterProcessor(processor)

	// Setup initial state: we have some namespaces, with one annotated
	// This simulates the scenario where we already have namespaces and one gets annotated
	watcher.allNamespaces.Insert("ns1", "ns2", "ns3", "annotated-ns")
	watcher.annotated.Insert("annotated-ns")
	watcher.global.Insert("annotated-ns") // marked as global
	watcher.filteringActive = true

	// Verify initial state: only annotated-ns should be global
	if !watcher.IsGlobalNamespace("annotated-ns") {
		t.Error("annotated-ns should be global")
	}
	if watcher.IsGlobalNamespace("ns1") {
		t.Error("ns1 should not be global when default is false and filtering is active")
	}

	// Now simulate removing the annotation from the last annotated namespace
	// This should trigger the backfill edge case
	ns := &slim_corev1.Namespace{}
	ns.Name = "annotated-ns"
	// No annotation, so hasAnnotation will be false

	// Clear the calls before testing
	calls = make([]string, 0)
	processor.calls = &calls

	watcher.updateNamespace(ns)

	// After removing the annotation, filtering should be inactive
	if watcher.filteringActive {
		t.Error("filtering should be inactive after removing the last annotation")
	}

	// All namespaces should now be global (backwards compatibility)
	if !watcher.IsGlobalNamespace("ns1") {
		t.Error("ns1 should be global after filtering becomes inactive")
	}
	if !watcher.IsGlobalNamespace("ns2") {
		t.Error("ns2 should be global after filtering becomes inactive")
	}
	if !watcher.IsGlobalNamespace("ns3") {
		t.Error("ns3 should be global after filtering becomes inactive")
	}
	if !watcher.IsGlobalNamespace("annotated-ns") {
		t.Error("annotated-ns should be global after filtering becomes inactive")
	}

	// Verify that processor was called for backfill
	// Should be called for the specific namespace that changed + all other namespaces for backfill
	if len(calls) < 3 { // at least ns1, ns2, ns3 should be backfilled (annotated-ns was already processed)
		t.Errorf("Expected at least 3 processor calls for backfill, got %d: %v", len(calls), calls)
	}

	// Check that all namespaces except the changed one were backfilled as global
	backfillCount := 0
	for _, call := range calls {
		if call == "ns1:true" || call == "ns2:true" || call == "ns3:true" {
			backfillCount++
		}
	}
	if backfillCount < 3 {
		t.Errorf("Expected 3 namespaces to be backfilled as global, got %d: %v", backfillCount, calls)
	}
}

func TestNamespaceWatcherConcurrentOperations(t *testing.T) {
	// Test concurrent annotation operations to ensure thread safety
	calls := make([]string, 0)
	processor := &mockProcessor{calls: &calls}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	watcher := NewNamespaceWatcher(logger, NamespaceWatcherConfig{DefaultGlobalNamespace: false})
	watcher.syncProcessing = true // Enable synchronous processing for testing
	watcher.RegisterProcessor(processor)

	// Add some initial namespaces
	watcher.allNamespaces.Insert("ns1", "ns2", "ns3")

	// Test rapid annotation/unannotation
	ns1 := &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{
		Name:        "ns1",
		Annotations: map[string]string{"clustermesh.cilium.io/global": "true"},
	}}

	ns2 := &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{
		Name:        "ns2",
		Annotations: map[string]string{"clustermesh.cilium.io/global": "false"},
	}}

	// Multiple rapid updates
	watcher.updateNamespace(ns1)
	watcher.updateNamespace(ns2)

	// Remove annotation from ns1
	ns1.Annotations = nil
	watcher.updateNamespace(ns1)

	// Verify final state
	if watcher.IsGlobalNamespace("ns2") {
		t.Error("ns2 should not be global with explicit false annotation")
	}

	if watcher.IsGlobalNamespace("ns1") {
		t.Error("ns1 should not be global after removing annotation with default=false")
	}
}

func TestNamespaceWatcherErrorHandling(t *testing.T) {
	// Test error handling with malformed annotations
	calls := make([]string, 0)
	processor := &mockProcessor{calls: &calls}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	watcher := NewNamespaceWatcher(logger, NamespaceWatcherConfig{DefaultGlobalNamespace: true})
	watcher.syncProcessing = true
	watcher.RegisterProcessor(processor)

	// Test with various malformed annotation values
	testCases := []struct {
		name           string
		annotation     string
		expectedGlobal bool
	}{
		{"empty annotation", "", true},        // should default to global (default=true, no annotation)
		{"invalid value", "invalid", false},   // should be treated as false (annotation exists but not "true")
		{"capitalized true", "True", false},   // should be treated as false (only "true" is valid)
		{"capitalized false", "False", false}, // should be treated as false
		{"numeric true", "1", false},          // should be treated as false (only "true" is valid)
		{"numeric false", "0", false},         // should be treated as false
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ns := &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{
				Name:        "test-ns",
				Annotations: map[string]string{"clustermesh.cilium.io/global": tc.annotation},
			}}

			// Clear annotations for empty test case
			if tc.annotation == "" {
				ns.Annotations = nil
			}

			watcher.updateNamespace(ns)

			if watcher.IsGlobalNamespace("test-ns") != tc.expectedGlobal {
				t.Errorf("Expected namespace to be global=%v for annotation '%s'", tc.expectedGlobal, tc.annotation)
			}
		})
	}
}

func TestNamespaceWatcherFilterTransitions(t *testing.T) {
	// Test all possible transitions between filtering active/inactive states
	calls := make([]string, 0)
	processor := &mockProcessor{calls: &calls}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	watcher := NewNamespaceWatcher(logger, NamespaceWatcherConfig{DefaultGlobalNamespace: false})
	watcher.syncProcessing = true
	watcher.RegisterProcessor(processor)

	// Add initial namespaces
	watcher.allNamespaces.Insert("ns1", "ns2", "ns3")

	// Initial state: no filtering, all global
	if !watcher.IsGlobalNamespace("ns1") {
		t.Error("Initially, all namespaces should be global")
	}

	// Transition 1: inactive -> active (first annotation added)
	ns1 := &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{
		Name:        "ns1",
		Annotations: map[string]string{"clustermesh.cilium.io/global": "true"},
	}}
	watcher.updateNamespace(ns1)

	if !watcher.filteringActive {
		t.Error("Filtering should be active after first annotation")
	}
	if !watcher.IsGlobalNamespace("ns1") {
		t.Error("ns1 should be global")
	}
	if watcher.IsGlobalNamespace("ns2") {
		t.Error("ns2 should not be global (default=false)")
	}

	// Add second annotation
	ns2 := &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{
		Name:        "ns2",
		Annotations: map[string]string{"clustermesh.cilium.io/global": "false"},
	}}
	watcher.updateNamespace(ns2)

	if watcher.annotated.Len() != 2 {
		t.Error("Should have 2 annotated namespaces")
	}

	// Transition 2: active -> inactive (remove all annotations)
	ns1.Annotations = nil
	watcher.updateNamespace(ns1)

	ns2.Annotations = nil
	watcher.updateNamespace(ns2)

	if watcher.filteringActive {
		t.Error("Filtering should be inactive after removing all annotations")
	}

	// All namespaces should be global again
	if !watcher.IsGlobalNamespace("ns1") || !watcher.IsGlobalNamespace("ns2") || !watcher.IsGlobalNamespace("ns3") {
		t.Error("All namespaces should be global when filtering is inactive")
	}
}

func TestNamespaceWatcherBackfillOnDelete(t *testing.T) {
	// Test the edge case for namespace deletion: when the last annotated namespace is deleted,
	// all remaining namespaces should become global

	// Create a mock processor to track calls
	calls := make([]string, 0)
	processor := &mockProcessor{calls: &calls}

	// Create a no-op logger to avoid nil pointer panics
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	watcher := NewNamespaceWatcher(logger, NamespaceWatcherConfig{DefaultGlobalNamespace: false})
	watcher.syncProcessing = true // Enable synchronous processing for testing
	watcher.RegisterProcessor(processor)

	// Setup initial state with multiple namespaces, one annotated
	watcher.allNamespaces.Insert("ns1", "ns2", "ns3", "annotated-ns")
	watcher.annotated.Insert("annotated-ns")
	watcher.global.Insert("annotated-ns")
	watcher.filteringActive = true

	// Clear the calls before testing
	calls = make([]string, 0)
	processor.calls = &calls

	// Delete the last annotated namespace
	ns := &slim_corev1.Namespace{}
	ns.Name = "annotated-ns"

	watcher.deleteNamespace(ns)

	// After deleting the last annotated namespace, filtering should be inactive
	if watcher.filteringActive {
		t.Error("filtering should be inactive after deleting the last annotated namespace")
	}

	// All remaining namespaces should now be global
	if !watcher.IsGlobalNamespace("ns1") {
		t.Error("ns1 should be global after filtering becomes inactive")
	}
	if !watcher.IsGlobalNamespace("ns2") {
		t.Error("ns2 should be global after filtering becomes inactive")
	}
	if !watcher.IsGlobalNamespace("ns3") {
		t.Error("ns3 should be global after filtering becomes inactive")
	}

	// Verify that processor was called for the deleted namespace + all remaining for backfill
	// Should be called for deleted namespace (false) + remaining namespaces (true)
	if len(calls) < 4 { // annotated-ns:false + ns1:true + ns2:true + ns3:true
		t.Errorf("Expected at least 4 processor calls (1 delete + 3 backfill), got %d: %v", len(calls), calls)
	}

	// Check the deleted namespace
	foundDelete := false
	for _, call := range calls {
		if call == "annotated-ns:false" {
			foundDelete = true
			break
		}
	}
	if !foundDelete {
		t.Error("Expected processor call for deleted namespace, but not found in calls:", calls)
	}

	// Check that remaining namespaces were backfilled as global
	backfillCount := 0
	for _, call := range calls {
		if call == "ns1:true" || call == "ns2:true" || call == "ns3:true" {
			backfillCount++
		}
	}
	if backfillCount < 3 {
		t.Errorf("Expected 3 namespaces to be backfilled as global, got %d: %v", backfillCount, calls)
	}
}

// mockProcessor implements NamespaceProcessor for testing
type mockProcessor struct {
	calls *[]string
}

func (mp *mockProcessor) ProcessNamespaceChange(namespace string, isGlobal bool) {
	call := fmt.Sprintf("%s:%t", namespace, isGlobal)
	*mp.calls = append(*mp.calls, call)
}

func TestNamespaceWatcherFilterActivationCleanup(t *testing.T) {
	// Test the edge case: when the first namespace is annotated (filtering activation),
	// all resources from non-global namespaces should be removed from etcd

	// Create a mock processor to track calls
	calls := make([]string, 0)
	processor := &mockProcessor{calls: &calls}

	// Create a no-op logger to avoid nil pointer panics
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	watcher := NewNamespaceWatcher(logger, NamespaceWatcherConfig{DefaultGlobalNamespace: false})
	watcher.syncProcessing = true // Enable synchronous processing for testing
	watcher.RegisterProcessor(processor)

	// Setup initial state: we have some namespaces, but none are annotated (filtering inactive)
	// In this state, all namespaces would have been exporting to etcd (backwards compatibility)
	watcher.allNamespaces.Insert("ns1", "ns2", "ns3", "to-be-global")
	watcher.filteringActive = false // No namespaces annotated yet

	// Verify initial state: all namespaces should be global (backwards compatibility)
	if !watcher.IsGlobalNamespace("ns1") {
		t.Error("ns1 should be global when filtering is inactive")
	}
	if !watcher.IsGlobalNamespace("ns2") {
		t.Error("ns2 should be global when filtering is inactive")
	}
	if !watcher.IsGlobalNamespace("to-be-global") {
		t.Error("to-be-global should be global when filtering is inactive")
	}

	// Now annotate the first namespace, which should activate filtering
	// This should trigger cleanup of resources from non-global namespaces
	ns := &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{
		Name:        "to-be-global",
		Annotations: map[string]string{"clustermesh.cilium.io/global": "true"},
	}}

	// Clear the calls before testing
	calls = make([]string, 0)
	processor.calls = &calls

	watcher.updateNamespace(ns)

	// After adding the first annotation, filtering should be active
	if !watcher.filteringActive {
		t.Error("filtering should be active after adding the first annotation")
	}

	// Now only the annotated namespace should be global (default is false)
	if !watcher.IsGlobalNamespace("to-be-global") {
		t.Error("to-be-global should be global with explicit true annotation")
	}
	if watcher.IsGlobalNamespace("ns1") {
		t.Error("ns1 should not be global when filtering is active with default=false")
	}
	if watcher.IsGlobalNamespace("ns2") {
		t.Error("ns2 should not be global when filtering is active with default=false")
	}
	if watcher.IsGlobalNamespace("ns3") {
		t.Error("ns3 should not be global when filtering is active with default=false")
	}

	// Verify that processor was called for cleanup
	// Should be called for the specific namespace that was annotated + cleanup calls for non-global namespaces
	if len(calls) < 4 { // to-be-global:true + ns1:false + ns2:false + ns3:false
		t.Errorf("Expected at least 4 processor calls (1 for annotated namespace + 3 cleanup), got %d: %v", len(calls), calls)
	}

	// Check that the annotated namespace was processed as global
	foundAnnotatedTrue := false
	for _, call := range calls {
		if call == "to-be-global:true" {
			foundAnnotatedTrue = true
			break
		}
	}
	if !foundAnnotatedTrue {
		t.Error("Expected processor call for annotated namespace as global, but not found in calls:", calls)
	}

	// Check that other namespaces were cleaned up (marked as non-global)
	cleanupCount := 0
	for _, call := range calls {
		if call == "ns1:false" || call == "ns2:false" || call == "ns3:false" {
			cleanupCount++
		}
	}
	if cleanupCount < 3 {
		t.Errorf("Expected 3 namespaces to be cleaned up (marked non-global), got %d: %v", cleanupCount, calls)
	}
}
