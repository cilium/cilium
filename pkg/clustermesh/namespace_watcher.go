// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"log/slog"
	"os"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// GlobalNamespaceTracker tracks which namespaces are marked as global for ClusterMesh export.
type GlobalNamespaceTracker interface {
	// IsGlobalNamespace returns true if the given namespace should be exported globally.
	// Returns true by default for backwards compatibility if no specific configuration exists.
	IsGlobalNamespace(namespace string) bool

	// GetGlobalNamespaces returns the set of namespaces that are currently marked as global.
	GetGlobalNamespaces() sets.Set[string]

	// RegisterProcessor registers a processor that will be notified when namespace status changes
	RegisterProcessor(processor NamespaceProcessor)

	// IsFilteringActive returns true if namespace-based filtering is currently active
	IsFilteringActive() bool
}

// NamespaceProcessor handles processing when namespace global status changes
type NamespaceProcessor interface {
	ProcessNamespaceChange(namespace string, isGlobal bool)
	// GetAllNamespaces returns all namespaces that have resources in this processor's resource index
	GetAllNamespaces() []string
}

// NamespaceWatcherConfig configures the namespace watcher behavior.
type NamespaceWatcherConfig struct {
	// DefaultGlobalNamespace determines the default behavior for namespaces when
	// namespace-based filtering is active (i.e., when at least one namespace is annotated).
	// When true, namespaces are global by default unless annotated with clustermesh.cilium.io/global=false.
	// When false, namespaces are local by default unless annotated with clustermesh.cilium.io/global=true.
	DefaultGlobalNamespace bool
}

type namespaceWatcher struct {
	logger            *slog.Logger
	config            NamespaceWatcherConfig
	mu                lock.RWMutex
	namespaceResource resource.Resource[*slim_corev1.Namespace]

	// Processors for handling namespace changes
	processors []NamespaceProcessor

	// For testing: if true, use synchronous processing
	syncProcessing bool
}

// NewNamespaceWatcher creates a new namespace watcher that tracks global namespaces.
func NewNamespaceWatcher(logger *slog.Logger, config NamespaceWatcherConfig) *namespaceWatcher {
	return &namespaceWatcher{
		logger: logger,
		config: config,
	}
}

// NewNamespaceWatcherFromEnv creates a new namespace watcher with configuration from environment variables.
// This is useful for components that don't have direct access to configuration but need namespace filtering.
func NewNamespaceWatcherFromEnv() *namespaceWatcher {
	// Read the configuration from environment variable following the same pattern as cluster-id
	defaultGlobal := false // Default to false for security
	if envVal := os.Getenv("CLUSTERMESH_DEFAULT_GLOBAL_NAMESPACE"); envVal != "" {
		if parsed, err := strconv.ParseBool(envVal); err == nil {
			defaultGlobal = parsed
		}
	}

	config := NamespaceWatcherConfig{
		DefaultGlobalNamespace: defaultGlobal,
	}

	return &namespaceWatcher{
		config: config,
	}
}

func (nw *namespaceWatcher) RegisterProcessor(processor NamespaceProcessor) {
	nw.mu.Lock()
	defer nw.mu.Unlock()
	nw.processors = append(nw.processors, processor)
}

// SetNamespaceResource sets the namespace resource for the watcher.
// This should be called during initialization when the namespace resource becomes available.
func (nw *namespaceWatcher) SetNamespaceResource(namespaces resource.Resource[*slim_corev1.Namespace]) {
	nw.mu.Lock()
	defer nw.mu.Unlock()
	nw.namespaceResource = namespaces
}

// getAllNamespacesFromProcessors gets all namespaces from all registered processors
func (nw *namespaceWatcher) getAllNamespacesFromProcessors() []string {
	allNamespaces := sets.New[string]()

	// Collect namespaces from all processors
	for _, processor := range nw.processors {
		namespaces := processor.GetAllNamespaces()
		for _, ns := range namespaces {
			allNamespaces.Insert(ns)
		}
	}

	return allNamespaces.UnsortedList()
}

// isNamespaceAnnotated checks if a namespace has the global annotation by querying the resource store
func (nw *namespaceWatcher) isNamespaceAnnotated(namespace string) bool {
	if nw.namespaceResource == nil {
		return false
	}

	ctx := context.Background()
	store, err := nw.namespaceResource.Store(ctx)
	if err != nil {
		return false
	}

	ns, exists, err := store.GetByKey(resource.Key{Name: namespace})
	if err != nil || !exists {
		return false
	}

	_, hasAnnotation := annotation.Get(ns, annotation.GlobalNamespace)
	return hasAnnotation
}

// isNamespaceGlobalByAnnotation checks if a namespace is marked as global by its annotation
func (nw *namespaceWatcher) isNamespaceGlobalByAnnotation(namespace string) bool {
	if nw.namespaceResource == nil {
		return false
	}

	ctx := context.Background()
	store, err := nw.namespaceResource.Store(ctx)
	if err != nil {
		return false
	}

	ns, exists, err := store.GetByKey(resource.Key{Name: namespace})
	if err != nil || !exists {
		return false
	}

	annotationValue, hasAnnotation := annotation.Get(ns, annotation.GlobalNamespace)
	if !hasAnnotation {
		return false
	}

	return annotationValue == "true"
}

// isFilteringActive checks if namespace-based filtering is currently active by checking if any namespace has the annotation
func (nw *namespaceWatcher) isFilteringActive() bool {
	if nw.namespaceResource == nil {
		return false
	}

	ctx := context.Background()
	store, err := nw.namespaceResource.Store(ctx)
	if err != nil {
		return false
	}

	// List all namespaces and check if any have the annotation
	allNamespaces := store.List()
	for _, ns := range allNamespaces {
		if _, hasAnnotation := annotation.Get(ns, annotation.GlobalNamespace); hasAnnotation {
			return true
		}
	}

	return false
}

func (nw *namespaceWatcher) IsGlobalNamespace(namespace string) bool {
	nw.mu.RLock()
	defer nw.mu.RUnlock()

	// If namespace-based filtering is not active (no annotated namespaces),
	// all namespaces are global for backwards compatibility
	if !nw.isFilteringActive() {
		return true
	}

	// If the namespace is explicitly annotated, use the annotation value
	if nw.isNamespaceAnnotated(namespace) {
		return nw.isNamespaceGlobalByAnnotation(namespace)
	}

	// For non-annotated namespaces when filtering is active, use the default behavior
	return nw.config.DefaultGlobalNamespace
}

func (nw *namespaceWatcher) IsFilteringActive() bool {
	nw.mu.RLock()
	defer nw.mu.RUnlock()
	return nw.isFilteringActive()
}

func (nw *namespaceWatcher) GetGlobalNamespaces() sets.Set[string] {
	nw.mu.RLock()
	defer nw.mu.RUnlock()

	// If namespace-based filtering is not active, return empty set to indicate all namespaces are global
	if !nw.isFilteringActive() {
		return sets.New[string]()
	}

	// When filtering is active, collect all global namespaces from the resource store
	result := sets.New[string]()

	if nw.namespaceResource == nil {
		return result
	}

	ctx := context.Background()
	store, err := nw.namespaceResource.Store(ctx)
	if err != nil {
		return result
	}

	// List all namespaces and check which ones are global
	allNamespaces := store.List()
	for _, ns := range allNamespaces {
		annotationValue, hasAnnotation := annotation.Get(ns, annotation.GlobalNamespace)
		if hasAnnotation {
			if annotationValue == "true" {
				result.Insert(ns.Name)
			}
		} else if nw.config.DefaultGlobalNamespace {
			// Non-annotated namespaces are global if the default is true
			result.Insert(ns.Name)
		}
	}

	return result
}

func (nw *namespaceWatcher) processNamespaceChange(processors []NamespaceProcessor, namespace string, isGlobal bool) {
	if nw.syncProcessing {
		// For testing: process synchronously
		nw.processNamespaceChangeSync(processors, namespace, isGlobal)
	} else {
		// Normal operation: process asynchronously
		for _, processor := range processors {
			go processor.ProcessNamespaceChange(namespace, isGlobal)
		}
	}
}

// processNamespaceChangeSync is a synchronous version for testing
func (nw *namespaceWatcher) processNamespaceChangeSync(processors []NamespaceProcessor, namespace string, isGlobal bool) {
	// Process the namespace change synchronously for testing
	for _, processor := range processors {
		processor.ProcessNamespaceChange(namespace, isGlobal)
	}
}

func (nw *namespaceWatcher) updateNamespace(ns *slim_corev1.Namespace) {
	// Check if namespace has the global annotation
	annotationValue, hasAnnotation := annotation.Get(ns, annotation.GlobalNamespace)

	nw.mu.Lock()

	// Capture the previous state by querying the resource store
	wasAnnotated := nw.isNamespaceAnnotated(ns.Name)
	wasGlobal := nw.isNamespaceGlobalByAnnotation(ns.Name)
	wasFilteringActive := nw.isFilteringActive()

	// Copy processors while holding the lock to avoid the double locking issue
	var processors []NamespaceProcessor
	processors = make([]NamespaceProcessor, len(nw.processors))
	copy(processors, nw.processors)

	nw.mu.Unlock()

	// Calculate current global status after the namespace update
	// We need to check the current filtering state and annotation status
	isFilteringActiveNow := hasAnnotation || nw.hasOtherAnnotatedNamespaces(ns.Name)
	isGlobal := nw.calculateGlobalStatus(ns.Name, hasAnnotation, annotationValue, isFilteringActiveNow)

	// Check if this specific namespace's status changed
	wasGlobalWithOldLogic := wasAnnotated && wasGlobal || (!wasAnnotated && nw.config.DefaultGlobalNamespace)
	needsProcessing := (wasGlobalWithOldLogic != isGlobal)

	// Check if we transitioned from filtering active to inactive (backfill case)
	transitionedToInactive := wasFilteringActive && !isFilteringActiveNow

	// Check if we transitioned from filtering inactive to active (cleanup case)
	transitionedToActive := !wasFilteringActive && isFilteringActiveNow

	if needsProcessing {
		if nw.logger != nil {
			nw.logger.Info("Namespace global status changed",
				logfields.K8sNamespace, ns.Name,
				"isGlobal", isGlobal,
				"hasAnnotation", hasAnnotation,
				"filteringActive", isFilteringActiveNow,
			)
		}

		// Process the namespace change directly without acquiring additional locks
		nw.processNamespaceChange(processors, ns.Name, isGlobal)
	}

	// Handle the edge case: if we transitioned from filtering active to inactive,
	// we need to backfill all namespaces as they all become global now
	if transitionedToInactive {
		// Get all namespaces from resource indexes
		namespacesToBackfill := nw.getAllNamespacesFromProcessors()

		if nw.logger != nil {
			nw.logger.Info("Namespace filtering deactivated, backfilling all namespaces as global",
				"namespacesToBackfill", len(namespacesToBackfill),
			)
		}

		for _, namespaceName := range namespacesToBackfill {
			// Skip the namespace we already processed above to avoid double processing
			if namespaceName != ns.Name {
				nw.processNamespaceChange(processors, namespaceName, true)
			}
		}
	}

	// Handle the edge case: if we transitioned from filtering inactive to active,
	// we need to remove resources from all non-global namespaces
	if transitionedToActive {
		// Get all namespaces from resource indexes
		namespacesToCleanup := nw.getAllNamespacesFromProcessors()

		if nw.logger != nil {
			nw.logger.Info("Namespace filtering activated, cleaning up non-global namespaces",
				"namespacesToCleanup", len(namespacesToCleanup),
			)
		}

		for _, namespaceName := range namespacesToCleanup {
			// Skip the namespace we already processed above to avoid double processing
			if namespaceName != ns.Name {
				// Check if this namespace should now be considered global
				shouldBeGlobal := nw.calculateGlobalStatusForNamespace(namespaceName, true)
				if !shouldBeGlobal {
					// This namespace is not global, so remove its resources from etcd
					nw.processNamespaceChange(processors, namespaceName, false)
				}
			}
		}
	}
}

// hasOtherAnnotatedNamespaces checks if there are any other namespaces (besides the given one) that have annotations
func (nw *namespaceWatcher) hasOtherAnnotatedNamespaces(excludeNamespace string) bool {
	if nw.namespaceResource == nil {
		return false
	}

	ctx := context.Background()
	store, err := nw.namespaceResource.Store(ctx)
	if err != nil {
		return false
	}

	allNamespaces := store.List()
	for _, ns := range allNamespaces {
		if ns.Name != excludeNamespace {
			if _, hasAnnotation := annotation.Get(ns, annotation.GlobalNamespace); hasAnnotation {
				return true
			}
		}
	}

	return false
}

// calculateGlobalStatus determines if a namespace should be global based on its annotation and filtering state
func (nw *namespaceWatcher) calculateGlobalStatus(namespace string, hasAnnotation bool, annotationValue string, filteringActive bool) bool {
	if !filteringActive {
		return true // All namespaces are global when filtering is not active
	}

	if hasAnnotation {
		return annotationValue == "true"
	}

	return nw.config.DefaultGlobalNamespace
}

// calculateGlobalStatusForNamespace determines if a namespace should be global when filtering is active
func (nw *namespaceWatcher) calculateGlobalStatusForNamespace(namespace string, filteringActive bool) bool {
	if !filteringActive {
		return true
	}

	if nw.isNamespaceAnnotated(namespace) {
		return nw.isNamespaceGlobalByAnnotation(namespace)
	}

	return nw.config.DefaultGlobalNamespace
}

func (nw *namespaceWatcher) deleteNamespace(ns *slim_corev1.Namespace) {
	nw.mu.Lock()

	// Capture the previous state by querying the resource store before deletion
	wasAnnotated := nw.isNamespaceAnnotated(ns.Name)
	wasGlobal := nw.isNamespaceGlobalByAnnotation(ns.Name)
	wasFilteringActive := nw.isFilteringActive()

	// Copy processors while holding the lock
	var processors []NamespaceProcessor
	processors = make([]NamespaceProcessor, len(nw.processors))
	copy(processors, nw.processors)

	nw.mu.Unlock()

	// Check if this namespace was global (either explicitly or by default)
	needsProcessing := wasAnnotated && wasGlobal || (!wasAnnotated && nw.config.DefaultGlobalNamespace)

	// Check if we transitioned from filtering active to inactive (backfill case)
	// This happens when the deleted namespace was the last one with annotations
	transitionedToInactive := wasFilteringActive && !nw.hasOtherAnnotatedNamespaces(ns.Name)

	// If this namespace was global (either explicitly or by default), process removal
	if needsProcessing {
		if nw.logger != nil {
			nw.logger.Info("Namespace deleted, removing from global set",
				logfields.K8sNamespace, ns.Name,
			)
		}
		nw.processNamespaceChange(processors, ns.Name, false)
	}

	// Handle the edge case: if we transitioned from filtering active to inactive,
	// we need to backfill all remaining namespaces as they all become global now
	if transitionedToInactive {
		// Get all namespaces from resource indexes
		namespacesToBackfill := nw.getAllNamespacesFromProcessors()

		if nw.logger != nil {
			nw.logger.Info("Namespace filtering deactivated due to namespace deletion, backfilling all remaining namespaces as global",
				"namespacesToBackfill", len(namespacesToBackfill),
				"deletedNamespace", ns.Name,
			)
		}

		for _, namespaceName := range namespacesToBackfill {
			nw.processNamespaceChange(processors, namespaceName, true)
		}
	}
}

// EnableSyncProcessing enables synchronous processing for testing purposes
func (nw *namespaceWatcher) EnableSyncProcessing() {
	nw.syncProcessing = true
}

// NamespaceWatcherParams provides the dependencies for the namespace watcher.
type NamespaceWatcherParams struct {
	cell.In

	Logger     *slog.Logger
	JobGroup   job.Group
	Namespaces resource.Resource[*slim_corev1.Namespace] `optional:"true"`
	Config     NamespaceWatcherConfig
}

// RegisterNamespaceWatcher registers the namespace watcher job.
func RegisterNamespaceWatcher(params NamespaceWatcherParams) GlobalNamespaceTracker {
	watcher := NewNamespaceWatcher(params.Logger, params.Config)
	watcher.SetNamespaceResource(params.Namespaces)

	if params.Namespaces == nil {
		params.Logger.Info("Namespace watching disabled - treating all namespaces as global")
		return watcher
	}

	params.JobGroup.Add(
		job.OneShot(
			"namespace-watcher",
			func(ctx context.Context, _ cell.Health) error {
				for event := range params.Namespaces.Events(ctx) {
					event.Done(nil)

					switch event.Kind {
					case resource.Sync:
						params.Logger.Info("Initial list of namespaces successfully received from Kubernetes")
					case resource.Upsert:
						watcher.updateNamespace(event.Object)
					case resource.Delete:
						watcher.deleteNamespace(event.Object)
					}
				}
				return nil
			},
		),
	)

	return watcher
}

// Global singleton instance for backward compatibility
var globalNamespaceTracker *namespaceWatcher

// GetGlobalNamespaceTracker returns the singleton namespace tracker for the main clustermesh package.
func GetGlobalNamespaceTracker() GlobalNamespaceTracker {
	if globalNamespaceTracker == nil {
		globalNamespaceTracker = NewNamespaceWatcherFromEnv()
	}
	return globalNamespaceTracker
}

// SetGlobalNamespaceResource sets the namespace resource for the global tracker.
// This should be called during initialization when the namespace resource becomes available.
func SetGlobalNamespaceResource(namespaces resource.Resource[*slim_corev1.Namespace]) {
	tracker := GetGlobalNamespaceTracker().(*namespaceWatcher)
	tracker.SetNamespaceResource(namespaces)
}

// IsGlobalServiceWithNamespaceFilter checks if a service is global considering both
// the service annotation and namespace filtering when active.
func IsGlobalServiceWithNamespaceFilter(obj interface{ GetAnnotations() map[string]string }, namespace string) bool {
	tracker := GetGlobalNamespaceTracker()
	return annotation.GetAnnotationIncludeExternalWithNamespaceFilter(
		obj, namespace, tracker.IsGlobalNamespace, tracker.IsFilteringActive,
	)
}
