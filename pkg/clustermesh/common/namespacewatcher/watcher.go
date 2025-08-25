// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namespacewatcher

import (
	"context"
	"log/slog"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// NewAlwaysGlobalTracker returns a tracker that always considers all namespaces as global.
// This is used for backward compatibility when namespace filtering is not enabled.
func NewAlwaysGlobalTracker() GlobalNamespaceTracker {
	return &alwaysGlobalTracker{}
}

// alwaysGlobalTracker is used for backward compatibility when namespace watching is not enabled
type alwaysGlobalTracker struct{}

func (d *alwaysGlobalTracker) IsGlobalNamespace(namespace string) bool        { return true }
func (d *alwaysGlobalTracker) GetGlobalNamespaces() sets.Set[string]          { return sets.New[string]() }
func (d *alwaysGlobalTracker) RegisterProcessor(processor NamespaceProcessor) {}
func (d *alwaysGlobalTracker) IsFilteringActive() bool                        { return false }
func (d *alwaysGlobalTracker) IsGlobalService(obj interface {
	GetAnnotations() map[string]string
	GetNamespace() string
}) bool {
	return annotation.GetAnnotationIncludeExternal(obj)
}
func (d *alwaysGlobalTracker) IsSharedGlobalService(obj interface {
	GetAnnotations() map[string]string
	GetNamespace() string
}) bool {
	return d.IsGlobalService(obj) && annotation.GetAnnotationShared(obj)
}

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

	// IsGlobalService checks if a service is global considering both
	// the service annotation and namespace filtering when active.
	IsGlobalService(obj interface {
		GetAnnotations() map[string]string
		GetNamespace() string
	}) bool

	// IsSharedGlobalService checks if a service is both global and shared
	IsSharedGlobalService(obj interface {
		GetAnnotations() map[string]string
		GetNamespace() string
	}) bool
}

// NamespaceProcessor handles processing when namespace global status changes
type NamespaceProcessor interface {
	ProcessNamespaceChange(namespace string, isGlobal bool)
	// GetAllNamespaces returns all namespaces that have resources in this processor's resource index
	GetAllNamespaces() []string
}

const (
	// OptClusterMeshDefaultGlobalNamespace is the name of the clustermesh-default-global-namespace option
	OptClusterMeshDefaultGlobalNamespace = "clustermesh-default-global-namespace"
)

// Config configures the namespace watcher behavior.
type Config struct {
	// DefaultGlobalNamespace determines the default behavior for namespaces when
	// namespace-based filtering is active (i.e., when at least one namespace is annotated).
	// When true, namespaces are global by default unless annotated with clustermesh.cilium.io/global=false.
	// When false, namespaces are local by default unless annotated with clustermesh.cilium.io/global=true.
	DefaultGlobalNamespace bool `mapstructure:"clustermesh-default-global-namespace"`
}

// Flags implements cell.Flagger to register the clustermesh-default-global-namespace flag.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(OptClusterMeshDefaultGlobalNamespace, cfg.DefaultGlobalNamespace,
		"Default behavior for namespaces when namespace-based filtering is active. "+
			"When true, namespaces are global by default unless annotated with 'clustermesh.cilium.io/global=false'. "+
			"When false, namespaces are local by default unless annotated with 'clustermesh.cilium.io/global=true'.")
}

type namespaceWatcher struct {
	logger            *slog.Logger
	config            Config
	mu                lock.RWMutex
	namespaceResource resource.Resource[*slim_corev1.Namespace]

	// Processors for handling namespace changes
	processors []NamespaceProcessor
}

// NewNamespaceWatcher creates a new namespace watcher that tracks global namespaces.
func NewNamespaceWatcher(logger *slog.Logger, config Config, namespaceResource resource.Resource[*slim_corev1.Namespace]) *namespaceWatcher {

	return &namespaceWatcher{
		logger:            logger,
		config:            config,
		namespaceResource: namespaceResource,
	}
}

func (nw *namespaceWatcher) RegisterProcessor(processor NamespaceProcessor) {
	nw.mu.Lock()
	defer nw.mu.Unlock()
	nw.processors = append(nw.processors, processor)
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

func (nw *namespaceWatcher) IsGlobalService(obj interface {
	GetAnnotations() map[string]string
	GetNamespace() string
}) bool {
	// First check if service has the global annotation
	if !annotation.GetAnnotationIncludeExternal(obj) {
		return false
	}

	// If namespace filtering is active, also check if service is in a global namespace
	if nw.IsFilteringActive() {
		if !nw.IsGlobalNamespace(obj.GetNamespace()) {
			// Service is marked as global but not in a global namespace
			return false
		}
	}

	return true
}

func (nw *namespaceWatcher) IsSharedGlobalService(obj interface {
	GetAnnotations() map[string]string
	GetNamespace() string
}) bool {
	// Service must be global first
	if !nw.IsGlobalService(obj) {
		return false
	}

	// Then check if it's also shared
	return annotation.GetAnnotationShared(obj)
}

func (nw *namespaceWatcher) processNamespaceChange(processors []NamespaceProcessor, namespace string, isGlobal bool) {

	// Normal operation: process asynchronously
	for _, processor := range processors {
		go processor.ProcessNamespaceChange(namespace, isGlobal)
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

	var processors = make([]NamespaceProcessor, len(nw.processors))
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
		nw.logger.Info("Namespace global status changed",
			logfields.K8sNamespace, ns.Name,
			logfields.IsGlobal, isGlobal,
			logfields.HasAnnotation, hasAnnotation,
			logfields.FilteringActive, isFilteringActiveNow,
		)

		// Process the namespace change directly without acquiring additional locks
		nw.processNamespaceChange(processors, ns.Name, isGlobal)
	}

	// Handle the edge case: if we transitioned from filtering active to inactive,
	// we need to backfill all namespaces as they all become global now
	if transitionedToInactive {
		// Get all namespaces from resource indexes
		namespacesToBackfill := nw.getAllNamespacesFromProcessors()

		nw.logger.Info("Namespace filtering deactivated, backfilling all namespaces as global",
			logfields.NamespacesToBackfill, len(namespacesToBackfill),
		)

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

		nw.logger.Info("Namespace filtering activated, cleaning up non-global namespaces",
			logfields.NamespacesToCleanup, len(namespacesToCleanup),
		)

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
	var processors = make([]NamespaceProcessor, len(nw.processors))
	copy(processors, nw.processors)

	nw.mu.Unlock()

	// Check if this namespace was global (either explicitly or by default)
	needsProcessing := wasAnnotated && wasGlobal || (!wasAnnotated && nw.config.DefaultGlobalNamespace)

	// Check if we transitioned from filtering active to inactive (backfill case)
	// This happens when the deleted namespace was the last one with annotations
	transitionedToInactive := wasFilteringActive && !nw.hasOtherAnnotatedNamespaces(ns.Name)

	// If this namespace was global (either explicitly or by default), process removal
	if needsProcessing {
		nw.logger.Info("Namespace deleted, removing from global set",
			logfields.K8sNamespace, ns.Name,
		)

		nw.processNamespaceChange(processors, ns.Name, false)
	}

	// Handle the edge case: if we transitioned from filtering active to inactive,
	// we need to backfill all remaining namespaces as they all become global now
	if transitionedToInactive {
		// Get all namespaces from resource indexes
		namespacesToBackfill := nw.getAllNamespacesFromProcessors()

		nw.logger.Info("Namespace filtering deactivated due to namespace deletion, backfilling all remaining namespaces as global",
			logfields.NamespacesToBackfill, len(namespacesToBackfill),
			logfields.DeletedNamespace, ns.Name,
		)

		for _, namespaceName := range namespacesToBackfill {
			nw.processNamespaceChange(processors, namespaceName, true)
		}
	}
}
