// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// GlobalNamespace is the annotation used to mark namespaces for global export in ClusterMesh
	GlobalNamespaceAnnotation = "clustermesh.cilium.io/global"
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
}

// NamespaceProcessor handles processing when namespace global status changes
type NamespaceProcessor interface {
	ProcessNamespaceChange(namespace string, isGlobal bool)
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
	logger          *slog.Logger
	config          NamespaceWatcherConfig
	mu              lock.RWMutex
	global          sets.Set[string]
	annotated       sets.Set[string] // Tracks which namespaces have the annotation (regardless of value)
	filteringActive bool             // True when at least one namespace is annotated

	// Processors for handling namespace changes
	processors []NamespaceProcessor
}

// NewNamespaceWatcher creates a new namespace watcher that tracks global namespaces.
func NewNamespaceWatcher(logger *slog.Logger, config NamespaceWatcherConfig) *namespaceWatcher {
	return &namespaceWatcher{
		logger:    logger,
		config:    config,
		global:    sets.New[string](),
		annotated: sets.New[string](),
	}
}

// RegisterProcessor registers a processor that will be notified when namespace status changes
func (nw *namespaceWatcher) RegisterProcessor(processor NamespaceProcessor) {
	nw.mu.Lock()
	defer nw.mu.Unlock()
	nw.processors = append(nw.processors, processor)
}

func (nw *namespaceWatcher) IsGlobalNamespace(namespace string) bool {
	nw.mu.RLock()
	defer nw.mu.RUnlock()

	// If namespace-based filtering is not active (no annotated namespaces),
	// all namespaces are global for backwards compatibility
	if !nw.filteringActive {
		return true
	}

	// If the namespace is explicitly annotated, use the annotation value
	if nw.annotated.Has(namespace) {
		return nw.global.Has(namespace)
	}

	// For non-annotated namespaces when filtering is active, use the default behavior
	return nw.config.DefaultGlobalNamespace
}

func (nw *namespaceWatcher) GetGlobalNamespaces() sets.Set[string] {
	nw.mu.RLock()
	defer nw.mu.RUnlock()

	// If namespace-based filtering is not active, return empty set to indicate all namespaces are global
	if !nw.filteringActive {
		return sets.New[string]()
	}

	// When filtering is active, we need to consider both annotated and non-annotated namespaces
	result := nw.global.Clone()

	// For this implementation, we return the explicitly global namespaces
	// The IsGlobalNamespace method handles the default behavior logic
	return result
}

func (nw *namespaceWatcher) processNamespaceChange(processors []NamespaceProcessor, namespace string, isGlobal bool) {
	// Process the namespace change directly by notifying all processors
	for _, processor := range processors {
		go processor.ProcessNamespaceChange(namespace, isGlobal)
	}
}

func (nw *namespaceWatcher) updateNamespace(ns *slim_corev1.Namespace) {
	// Check if namespace has the global annotation
	annotationValue, hasAnnotation := annotation.Get(ns, GlobalNamespaceAnnotation)

	nw.mu.Lock()

	wasAnnotated := nw.annotated.Has(ns.Name)
	wasGlobal := nw.global.Has(ns.Name)

	if hasAnnotation {
		nw.annotated.Insert(ns.Name)
		if annotationValue == "true" {
			nw.global.Insert(ns.Name)
		} else {
			nw.global.Delete(ns.Name)
		}
	} else {
		nw.annotated.Delete(ns.Name)
		nw.global.Delete(ns.Name)
	}

	// Update filtering active status
	nw.filteringActive = nw.annotated.Len() > 0

	// Calculate current global status
	isGlobal := nw.isGlobalNamespaceUnlocked(ns.Name)

	// Check if this specific namespace's status changed
	wasGlobalWithOldLogic := wasAnnotated && wasGlobal || (!wasAnnotated && nw.config.DefaultGlobalNamespace)
	needsProcessing := (wasGlobalWithOldLogic != isGlobal)

	// Copy processors while holding the lock to avoid the double locking issue
	var processors []NamespaceProcessor
	if needsProcessing {
		processors = make([]NamespaceProcessor, len(nw.processors))
		copy(processors, nw.processors)
	}

	nw.mu.Unlock()

	if needsProcessing {
		nw.logger.Info("Namespace global status changed",
			logfields.K8sNamespace, ns.Name,
			"isGlobal", isGlobal,
			"hasAnnotation", hasAnnotation,
			"filteringActive", nw.filteringActive,
		)

		// Process the namespace change directly without acquiring additional locks
		nw.processNamespaceChange(processors, ns.Name, isGlobal)
	}
}

// isGlobalNamespaceUnlocked is the unlocked version of IsGlobalNamespace for internal use
func (nw *namespaceWatcher) isGlobalNamespaceUnlocked(namespace string) bool {
	// If namespace-based filtering is not active (no annotated namespaces),
	// all namespaces are global for backwards compatibility
	if !nw.filteringActive {
		return true
	}

	// If the namespace is explicitly annotated, use the annotation value
	if nw.annotated.Has(namespace) {
		return nw.global.Has(namespace)
	}

	// For non-annotated namespaces when filtering is active, use the default behavior
	return nw.config.DefaultGlobalNamespace
}

func (nw *namespaceWatcher) deleteNamespace(ns *slim_corev1.Namespace) {
	nw.mu.Lock()
	wasAnnotated := nw.annotated.Has(ns.Name)
	wasGlobal := nw.global.Has(ns.Name)

	nw.annotated.Delete(ns.Name)
	nw.global.Delete(ns.Name)

	// Update filtering active status
	nw.filteringActive = nw.annotated.Len() > 0

	// Check if this namespace was global and copy processors if needed
	needsProcessing := wasAnnotated && wasGlobal || (!wasAnnotated && nw.config.DefaultGlobalNamespace)
	var processors []NamespaceProcessor
	if needsProcessing {
		processors = make([]NamespaceProcessor, len(nw.processors))
		copy(processors, nw.processors)
	}

	nw.mu.Unlock()

	// If this namespace was global (either explicitly or by default), process removal
	if needsProcessing {
		nw.logger.Info("Namespace deleted, removing from global set",
			logfields.K8sNamespace, ns.Name,
		)
		nw.processNamespaceChange(processors, ns.Name, false)
	}
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
