// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namespacewatcher

import (
	"log/slog"
	"strings"

	"github.com/spf13/pflag"
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

	// IsGlobalService checks if a service is global considering both
	// the service annotation and namespace filtering when active.
	// Expectation is this function will be invoked with
	// "github.com/cilium/cilium/pkg/loadbalancer".Service
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
	OnNamespaceGlobalChange(namespace string)
}

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
	flags.Bool("clustermesh-default-global-namespace", cfg.DefaultGlobalNamespace,
		"Default behavior for namespaces when namespace-based filtering is active. "+
			"When true, namespaces are global by default unless annotated with 'clustermesh.cilium.io/global=false'. "+
			"When false, namespaces are local by default unless annotated with 'clustermesh.cilium.io/global=true'.")
}

type namespaceWatcher struct {
	logger            *slog.Logger
	config            Config
	mu                lock.RWMutex
	namespaceResource resource.Resource[*slim_corev1.Namespace]
	nsStore           resource.Store[*slim_corev1.Namespace]

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

// isNamespaceAnnotated checks if a namespace has the global annotation by querying the resource store
func (nw *namespaceWatcher) isNamespaceAnnotated(namespace string) bool {
	ns, exists, err := nw.nsStore.GetByKey(resource.Key{Name: namespace})
	if err != nil || !exists {
		return false
	}

	_, hasAnnotation := annotation.Get(ns, annotation.GlobalNamespace)
	return hasAnnotation
}

// isNamespaceGlobalByAnnotation checks if a namespace is marked as global by its annotation
func (nw *namespaceWatcher) isNamespaceGlobalByAnnotation(namespace string) bool {
	ns, exists, err := nw.nsStore.GetByKey(resource.Key{Name: namespace})
	if err != nil || !exists {
		return false
	}

	annotationValue, hasAnnotation := annotation.Get(ns, annotation.GlobalNamespace)
	if !hasAnnotation {
		return false
	}

	return strings.ToLower(annotationValue) == "true"
}

func (nw *namespaceWatcher) IsGlobalNamespace(namespace string) bool {
	nw.mu.RLock()
	defer nw.mu.RUnlock()

	// If all namespaces are global by default (filtering inactive), then return true.
	// Otherwise, check the annotation status.
	return nw.config.DefaultGlobalNamespace || nw.isNamespaceGlobalByAnnotation(namespace)
}

func (nw *namespaceWatcher) GetGlobalNamespaces() sets.Set[string] {
	nw.mu.RLock()
	defer nw.mu.RUnlock()

	// When filtering is active, collect all global namespaces from the resource store
	result := sets.New[string]()

	// List all namespaces and check which ones are global
	allNamespaces := nw.nsStore.List()
	for _, ns := range allNamespaces {
		if nw.IsGlobalNamespace(ns.Name) {
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

	// If namespace filtering is not active, service is global.
	// If namespace filtering is active, also check if service is in a global namespace
	return nw.IsGlobalNamespace(obj.GetNamespace())
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
		processor.OnNamespaceGlobalChange(namespace)
	}
}

func (nw *namespaceWatcher) updateNamespace(ns *slim_corev1.Namespace) {
	nw.mu.Lock()

	// Capture the previous state by querying the resource store
	wasGlobal := nw.isNamespaceGlobalByAnnotation(ns.Name)

	var processors = make([]NamespaceProcessor, len(nw.processors))
	copy(processors, nw.processors)

	nw.mu.Unlock()

	// Calculate current global status after the namespace update
	// We need to check the current filtering state and annotation status
	isGlobal := nw.calculateGlobalStatus(ns)

	// Check if this specific namespace's status changed
	needsProcessing := wasGlobal != isGlobal

	if needsProcessing {
		nw.logger.Info("Namespace global status changed",
			logfields.K8sNamespace, ns.Name,
			logfields.IsGlobal, isGlobal,
		)

		// Process the namespace change directly without acquiring additional locks
		nw.processNamespaceChange(processors, ns.Name, isGlobal)
	}
}

// hasOtherAnnotatedNamespaces checks if there are any other namespaces (besides the given one) that have annotations
func (nw *namespaceWatcher) hasOtherAnnotatedNamespaces(excludeNamespace string) bool {
	allNamespaces := nw.nsStore.List()
	for _, ns := range allNamespaces {
		if ns.Name != excludeNamespace {
			if _, hasAnnotation := annotation.Get(ns, annotation.GlobalNamespace); hasAnnotation {
				return true
			}
		}
	}

	return false
}

// calculateGlobalStatus determines if a namespace should be global based on its annotation and filtering state.
// Returns true if the namespace is global.
func (nw *namespaceWatcher) calculateGlobalStatus(ns *slim_corev1.Namespace) bool {
	// Get global annotation for this namespace.
	annotationValue, hasAnnotation := annotation.Get(ns, annotation.GlobalNamespace)

	return nw.config.DefaultGlobalNamespace || (hasAnnotation && strings.ToLower(annotationValue) == "true")
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

	// Check if this namespace was global (either explicitly or by default)
	needsProcessing := nw.IsGlobalNamespace(ns.Name)

	// Copy processors while holding the lock
	var processors = make([]NamespaceProcessor, len(nw.processors))
	copy(processors, nw.processors)

	nw.mu.Unlock()

	// If this namespace was global (either explicitly or by default), process removal
	if needsProcessing {
		nw.logger.Info("Namespace deleted, removing from global set",
			logfields.K8sNamespace, ns.Name,
		)

		nw.processNamespaceChange(processors, ns.Name, false)
	}
}
