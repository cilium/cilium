// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// ManagedByOperator is the value set in the Status.ManagedBy field
	// to indicate the resource is managed by the operator
	ManagedByOperator = "operator"

	// AnnotationSourceClusterConfig is the annotation key to track which ClusterConfig created this NodeConfig
	AnnotationSourceClusterConfig = "cilium.io/source-cluster-config"

	// AnnotationHadSelector is the annotation key indicating the ClusterConfig had a label selector
	AnnotationHadSelector = "cilium.io/had-selector"

	// reconcileRetryInterval is the initial interval for the exponential backoff
	reconcileRetryInterval = 1 * time.Second

	// reconcileMaxRetries is the maximum number of reconciliation retries
	reconcileMaxRetries = 10
)

// ConfigReconcilerParams contains all dependencies required to create a ConfigReconciler instance.
// The reconciler watches CiliumNetworkDriverClusterConfig resources and creates/updates/deletes
// CiliumNetworkDriverNodeConfig resources for matching nodes based on label selectors.
type ConfigReconcilerParams struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle
	ClientSet k8s_client.Clientset
	JobGroup  job.Group

	// resource tracking
	ClusterConfigResource resource.Resource[*v2alpha1.CiliumNetworkDriverClusterConfig]
	NodeConfigResource    resource.Resource[*v2alpha1.CiliumNetworkDriverNodeConfig]
	CiliumNodes           resource.Resource[*v2.CiliumNode]
}

// ConfigReconciler is the main controller that reconciles CiliumNetworkDriverClusterConfig
// resources into CiliumNetworkDriverNodeConfig resources. It implements level-triggered
// reconciliation, meaning it examines the complete desired state on every reconciliation
// rather than processing individual events.
type ConfigReconciler struct {
	logger    *slog.Logger
	clientset k8s_client.Clientset
	lc        cell.Lifecycle
	jg        job.Group

	// Resources
	clusterConfig resource.Resource[*v2alpha1.CiliumNetworkDriverClusterConfig]
	nodeConfig    resource.Resource[*v2alpha1.CiliumNetworkDriverNodeConfig]
	ciliumNode    resource.Resource[*v2.CiliumNode]

	// State built from events
	mu             lock.RWMutex
	clusterConfigs map[resource.Key]*v2alpha1.CiliumNetworkDriverClusterConfig
	nodeConfigs    map[resource.Key]*v2alpha1.CiliumNetworkDriverNodeConfig
	ciliumNodes    map[resource.Key]*v2.CiliumNode

	// Client for NodeConfig writes
	nodeConfigClient cilium_client_v2alpha1.CiliumNetworkDriverNodeConfigInterface

	// Client for ClusterConfig status updates
	clusterConfigClient cilium_client_v2alpha1.CiliumNetworkDriverClusterConfigInterface

	// internal state
	reconcileCh chan struct{}
}

// registerConfigReconciler creates and registers a new ConfigReconciler operator instance.
// It initializes the reconciler with all necessary dependencies and registers the reconciliation
// jobs with the job group. If the Kubernetes clientset is not enabled, this function returns
// early without registering anything, allowing graceful degradation in test environments.
func registerConfigReconciler(params ConfigReconcilerParams) {
	if params.ClientSet == nil || !params.ClientSet.IsEnabled() {
		return
	}

	r := &ConfigReconciler{
		logger:         params.Log,
		clientset:      params.ClientSet,
		jg:             params.JobGroup,
		lc:             params.Lifecycle,
		reconcileCh:    make(chan struct{}, 1),
		clusterConfig:  params.ClusterConfigResource,
		nodeConfig:     params.NodeConfigResource,
		ciliumNode:     params.CiliumNodes,
		clusterConfigs: make(map[resource.Key]*v2alpha1.CiliumNetworkDriverClusterConfig),
		nodeConfigs:    make(map[resource.Key]*v2alpha1.CiliumNetworkDriverNodeConfig),
		ciliumNodes:    make(map[resource.Key]*v2.CiliumNode),
	}

	r.nodeConfigClient = r.clientset.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs()
	r.clusterConfigClient = r.clientset.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs()

	params.Lifecycle.Append(r)
}

// Start registers a single job that handles all resource watching and reconciliation.
// The job multiplexes events from ClusterConfig, NodeConfig, and CiliumNode resources using
// a select statement, triggering reconciliation whenever any relevant resource changes.
// This approach consolidates event handling into a single goroutine for simplicity.
func (r *ConfigReconciler) Start(ctx cell.HookContext) error {
	// clientset is nil or feature is disabled.
	if r.clusterConfig == nil || r.nodeConfig == nil || r.ciliumNode == nil {
		return nil
	}

	clusterConfigSynced := make(chan struct{})
	nodeConfigSynced := make(chan struct{})
	ciliumNodeSynced := make(chan struct{})

	r.jg.Add(
		job.OneShot("network-driver-config-clusterconfig-watcher", func(ctx context.Context, health cell.Health) error {
			var synced bool

			for ev := range r.clusterConfig.Events(ctx) {
				switch ev.Kind {
				case resource.Sync:
					r.logger.Info("All CiliumNetworkDriverClusterConfig resources synchronized")
					close(clusterConfigSynced)
					synced = true

				case resource.Upsert:
					r.mu.Lock()
					r.clusterConfigs[ev.Key] = ev.Object
					r.mu.Unlock()
					if synced {
						r.triggerReconcile()
					}

				case resource.Delete:
					r.mu.Lock()
					delete(r.clusterConfigs, ev.Key)
					r.mu.Unlock()

					if synced {
						r.triggerReconcile()
					}
				}

				ev.Done(nil)
			}

			return nil
		}),

		job.OneShot("network-driver-config-nodeconfig-watcher", func(ctx context.Context, health cell.Health) error {
			var synced bool

			for ev := range r.nodeConfig.Events(ctx) {
				switch ev.Kind {
				case resource.Sync:
					r.logger.Info("All CiliumNetworkDriverNodeConfig resources synchronized")
					close(nodeConfigSynced)
					synced = true

				case resource.Upsert:
					r.mu.Lock()
					r.nodeConfigs[ev.Key] = ev.Object
					r.mu.Unlock()

					if synced {
						r.triggerReconcile()
					}

				case resource.Delete:
					r.mu.Lock()
					delete(r.nodeConfigs, ev.Key)
					r.mu.Unlock()

					if synced {
						r.triggerReconcile()
					}
				}

				ev.Done(nil)
			}

			return nil
		}),

		job.OneShot("network-driver-config-ciliumnode-watcher", func(ctx context.Context, health cell.Health) error {
			var synced bool

			for ev := range r.ciliumNode.Events(ctx) {
				switch ev.Kind {
				case resource.Sync:
					r.logger.Info("All CiliumNode resources synchronized")
					close(ciliumNodeSynced)
					synced = true

				case resource.Upsert:
					r.mu.Lock()
					r.ciliumNodes[ev.Key] = ev.Object
					r.mu.Unlock()

					if synced {
						r.triggerReconcile()
					}

				case resource.Delete:
					r.mu.Lock()
					delete(r.ciliumNodes, ev.Key)
					r.mu.Unlock()

					if synced {
						r.triggerReconcile()
					}
				}

				ev.Done(nil)
			}

			return nil
		}),

		job.OneShot("network-driver-config-reconciler", func(ctx context.Context, health cell.Health) error {
			// Wait for all resources to be synchronized
			<-clusterConfigSynced
			<-nodeConfigSynced
			<-ciliumNodeSynced

			r.logger.Info("Network Driver Config controller started - all resources synced")

			if err := r.Run(ctx); err != nil {
				r.logger.ErrorContext(ctx, "Reconciliation loop failed", logfields.Error, err)
				return err
			}

			return nil
		}),
	)

	return nil
}

// Stop is called when the lifecycle is stopping.
func (r *ConfigReconciler) Stop(ctx cell.HookContext) error {
	r.logger.Info("Network Driver Config controller stopping")
	return nil
}

// triggerReconcile initiates level-triggered reconciliation in a non-blocking manner.
// Multiple calls to this function coalesce into a single reconciliation due to the
// buffered channel with capacity 1. This prevents reconciliation storms when many
// resources change simultaneously.
func (r *ConfigReconciler) triggerReconcile() {
	select {
	case r.reconcileCh <- struct{}{}:
		r.logger.Debug("Network Driver Config reconciliation triggered")
	default:
		// Already queued, no need to queue again
	}
}

// Run executes the main reconciliation loop. It continuously processes reconciliation requests
// from the reconcileCh channel. Each reconciliation examines the complete desired
// state and brings the actual state in line with it.
func (r *ConfigReconciler) Run(ctx context.Context) (err error) {
	// Trigger initial reconciliation
	r.triggerReconcile()

	for {
		select {
		case <-ctx.Done():
			return

		case _, ok := <-r.reconcileCh:
			if !ok {
				return
			}

			err := r.reconcileWithRetry(ctx)
			if err != nil {
				r.logger.ErrorContext(ctx, "Network Driver Config reconciliation failed", logfields.Error, err)
			} else {
				r.logger.DebugContext(ctx, "Network Driver Config reconciliation successful")
			}
		}
	}
}

// reconcileWithRetry executes the reconcile function with exponential backoff retry logic.
// It retries up to reconcileMaxRetries times, with an initial interval of reconcileRetryInterval.
// Retryable errors (like conflicts or not found) are logged at debug level to reduce noise,
// while other errors are logged as warnings. Every 5th retry of a retryable error is logged
// as a warning to ensure visibility of persistent issues.
func (r *ConfigReconciler) reconcileWithRetry(ctx context.Context) error {
	return resiliency.Retry(ctx, reconcileRetryInterval, reconcileMaxRetries, func(ctx context.Context, retries int) (bool, error) {
		err := r.reconcile(ctx)

		switch {
		case err != nil:
			// Determine log level based on error type and retry count
			if isRetryableError(err) && retries%5 != 0 {
				r.logger.DebugContext(ctx, "Transient Network Driver Config reconciliation error", logfields.Error, err)
			} else {
				r.logger.WarnContext(ctx, "Network Driver Config reconciliation error", logfields.Error, err)
			}
			return false, nil // Continue retrying
		default:
			return true, nil // Success, stop retrying
		}
	})
}

// reconcile performs the actual reconciliation work. It examines all ClusterConfig resources
// and ensures that the corresponding NodeConfig resources exist and have the correct spec
// for all matching nodes. It also cleans up orphaned NodeConfig resources that are no longer
// selected by any ClusterConfig or whose nodes no longer exist.
func (r *ConfigReconciler) reconcile(ctx context.Context) error {
	var err error

	r.mu.RLock()
	configs := make([]*v2alpha1.CiliumNetworkDriverClusterConfig, 0, len(r.clusterConfigs))
	for _, config := range r.clusterConfigs {
		configs = append(configs, config)
	}
	r.mu.RUnlock()

	// Reconcile each cluster config
	for _, config := range configs {
		rcErr := r.reconcileClusterConfig(ctx, config)
		if rcErr != nil {
			err = errors.Join(err, rcErr)
		}
	}

	// Clean up orphaned node configs
	if cleanupErr := r.cleanupOrphanedNodeConfigs(ctx); cleanupErr != nil {
		err = errors.Join(err, cleanupErr)
	}

	return err
}

// reconcileClusterConfig processes a single CiliumNetworkDriverClusterConfig resource.
// It evaluates the node selector against all CiliumNode resources, creates or updates
// NodeConfig resources for matching nodes, deletes NodeConfigs for nodes that no
// longer match this ClusterConfig's selector, and updates the ClusterConfig status
// with any conflicts detected.
func (r *ConfigReconciler) reconcileClusterConfig(ctx context.Context, config *v2alpha1.CiliumNetworkDriverClusterConfig) error {
	matchingNodes, conflicts, err := r.upsertNodeConfigs(ctx, config)
	if err != nil {
		return err
	}

	// Update ClusterConfig status with conflicts
	if len(conflicts) > 0 {
		if statusErr := r.updateClusterConfigStatus(ctx, config, conflicts); statusErr != nil {
			// Log but don't fail reconciliation if status update fails
			r.logger.WarnContext(ctx, "Failed to update ClusterConfig status",
				logfields.Config, config.Name,
				logfields.Error, statusErr)
		}
	} else {
		// Clear conflict condition if no conflicts
		if statusErr := r.clearClusterConfigConflicts(ctx, config); statusErr != nil {
			r.logger.WarnContext(ctx, "Failed to clear ClusterConfig conflict status",
				logfields.Config, config.Name,
				logfields.Error, statusErr)
		}
	}

	if err := r.deleteOrphanedNodeConfigsForClusterConfig(ctx, matchingNodes, config); err != nil {
		return err
	}

	return nil
}

// upsertNodeConfigs creates or updates CiliumNetworkDriverNodeConfig resources for all nodes
// that match the provided ClusterConfig's node selector. It returns a set of node names that
// matched the selector, a list of conflicts detected, and any errors. User-created NodeConfigs
// (non-operator-managed) are preserved.
func (r *ConfigReconciler) upsertNodeConfigs(ctx context.Context, config *v2alpha1.CiliumNetworkDriverClusterConfig) (sets.Set[string], []*ConflictError, error) {
	var nodeSelector slim_labels.Selector
	var errs error
	var conflicts []*ConflictError

	if config.Spec.NodeSelector == nil {
		nodeSelector = slim_labels.Everything()
	} else {
		selector, err := slim_meta_v1.LabelSelectorAsSelector(config.Spec.NodeSelector)
		if err != nil {
			return nil, nil, err
		}
		nodeSelector = selector
	}

	matchingNodes := sets.New[string]()

	r.mu.RLock()
	nodes := make([]*v2.CiliumNode, 0, len(r.ciliumNodes))
	for _, node := range r.ciliumNodes {
		nodes = append(nodes, node)
	}
	r.mu.RUnlock()

	for _, node := range nodes {
		if !nodeSelector.Matches(slim_labels.Set(node.Labels)) {
			continue
		}

		matchingNodes.Insert(node.Name)

		r.mu.RLock()
		oldNodeConfig, oldNodeConfigExists := r.nodeConfigs[resource.Key{Name: node.Name}]
		r.mu.RUnlock()

		if oldNodeConfigExists && !isOperatorManaged(oldNodeConfig) {
			r.logger.InfoContext(
				ctx, "Skipping node config update - not managed by us",
				logfields.Node, node.Name,
			)

			continue
		}

		newNodeConfig := &v2alpha1.CiliumNetworkDriverNodeConfig{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: node.Name,
				Annotations: map[string]string{
					AnnotationSourceClusterConfig: config.Name,
					AnnotationHadSelector:         strconv.FormatBool(config.Spec.NodeSelector != nil),
				},
			},
			Spec: *config.Spec.Spec.DeepCopy(),
		}

		if oldNodeConfigExists {
			// Extract metadata from existing NodeConfig
			oldSourceConfig := oldNodeConfig.Annotations[AnnotationSourceClusterConfig]
			hadSelector := oldNodeConfig.Annotations[AnnotationHadSelector] == "true"

			// Check if the old source config still exists
			r.mu.RLock()
			_, oldConfigStillExists := r.clusterConfigs[resource.Key{Name: oldSourceConfig}]
			r.mu.RUnlock()

			// Apply conflict rules:
			// 1. Selector-based config trying to override another selector-based config: CONFLICT (block update)
			// 2. Selector-based config trying to override catch-all config: ALLOWED (update NodeConfig)
			// 3. Catch-all config trying to override ANY existing config: CONFLICT (block update)
			// 4. Any config can replace a deleted config: ALLOWED (update NodeConfig)

			if oldSourceConfig != config.Name {
				// Different config is trying to manage this node
				if oldConfigStillExists {
					// Old config still exists
					if hadSelector {
						// Old config had a selector
						if config.Spec.NodeSelector != nil {
							// New config also has selector: CONFLICT (rule 1)
							conflict := &ConflictError{
								NodeName:     node.Name,
								OldConfig:    oldSourceConfig,
								NewConfig:    config.Name,
								ConflictType: "selector-based-assignment",
							}
							conflicts = append(conflicts, conflict)

							r.logger.WarnContext(
								ctx, "Configuration conflict detected",
								logfields.Node, node.Name,
								logfields.OldConfig, oldSourceConfig,
								logfields.NewConfig, config.Name,
								logfields.ConflictType, "selector-based-assignment",
							)

							continue
						} else {
							// New config is catch-all: CONFLICT (rule 3)
							// Catch-all cannot override selector-based config
							conflict := &ConflictError{
								NodeName:     node.Name,
								OldConfig:    oldSourceConfig,
								NewConfig:    config.Name,
								ConflictType: "catch-all-blocked-by-selector",
							}
							conflicts = append(conflicts, conflict)

							r.logger.WarnContext(
								ctx, "Configuration conflict detected",
								logfields.Node, node.Name,
								logfields.OldConfig, oldSourceConfig,
								logfields.NewConfig, config.Name,
								logfields.ConflictType, "catch-all-blocked-by-selector",
							)

							continue
						}
					} else {
						// Old config had no selector (catch-all)
						if config.Spec.NodeSelector == nil {
							// New config also catch-all: CONFLICT (rule 3)
							conflict := &ConflictError{
								NodeName:     node.Name,
								OldConfig:    oldSourceConfig,
								NewConfig:    config.Name,
								ConflictType: "catch-all-override",
							}
							conflicts = append(conflicts, conflict)

							r.logger.WarnContext(
								ctx, "Configuration conflict detected",
								logfields.Node, node.Name,
								logfields.OldConfig, oldSourceConfig,
								logfields.NewConfig, config.Name,
								logfields.ConflictType, "catch-all-override",
							)

							continue
						}
						// Else: new config has selector, old was catch-all: ALLOWED (rule 2)
						// Fall through to update
					}
				}

				// At this point: either old config was deleted (rule 4), or selector overriding catch-all (rule 2)
				// This is allowed - update the NodeConfig
			} else {
				// Same config is managing this node - check if update is needed
				if oldNodeConfig.Spec.DeepEqual(&newNodeConfig.Spec) &&
					oldNodeConfig.Annotations[AnnotationHadSelector] == strconv.FormatBool(config.Spec.NodeSelector != nil) {
					// No changes needed
					matchingNodes.Insert(node.Name)
					continue
				}
				// Fall through to update
			}

			// Update the existing NodeConfig
			updatedConfig := oldNodeConfig.DeepCopy()
			updatedConfig.Spec = *config.Spec.Spec.DeepCopy()
			updatedConfig.Annotations[AnnotationSourceClusterConfig] = config.Name
			updatedConfig.Annotations[AnnotationHadSelector] = strconv.FormatBool(config.Spec.NodeSelector != nil)

			_, err := r.nodeConfigClient.Update(ctx, updatedConfig, meta_v1.UpdateOptions{})
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to update node config for node %s: %w", node.Name, err))
				continue
			}

			r.logger.InfoContext(
				ctx, "Updated node config",
				logfields.Node, node.Name,
				logfields.Config, config.Name,
			)

			matchingNodes.Insert(node.Name)
			continue
		}

		// if we get this far, it is a new config
		createdConfig, err := r.nodeConfigClient.Create(ctx, newNodeConfig, meta_v1.CreateOptions{})
		if err != nil {
			if k8serrors.IsAlreadyExists(err) {
				r.logger.Debug("Node config already exists", logfields.Node, node.Name)
			} else {
				errs = errors.Join(errs, fmt.Errorf("failed to create node config for node %s: %w", node.Name, err))
			}

			continue
		}

		createdConfig.Status.ManagedBy = ManagedByOperator
		_, err = r.nodeConfigClient.UpdateStatus(ctx, createdConfig, meta_v1.UpdateOptions{})
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to update node config status for node %s: %w", node.Name, err))
		}

		r.logger.InfoContext(
			ctx, "Created node config",
			logfields.Node, node.Name,
			logfields.Config, config.Name,
		)
	}

	return matchingNodes, conflicts, errs
}

// deleteOrphanedNodeConfigsForClusterConfig removes operator-managed NodeConfig resources
// that are no longer selected by the specified ClusterConfig. It verifies whether other
// ClusterConfigs still select each node before deletion.
func (r *ConfigReconciler) deleteOrphanedNodeConfigsForClusterConfig(ctx context.Context, matchingNodes sets.Set[string], config *v2alpha1.CiliumNetworkDriverClusterConfig) error {
	var errs error

	r.mu.RLock()

	allNodes := sets.New[string]()
	for _, node := range r.ciliumNodes {
		allNodes.Insert(node.Name)
	}

	r.mu.RUnlock()

	orphanedNodes := allNodes.Difference(matchingNodes)

	for nodeName := range orphanedNodes {
		r.mu.RLock()
		nodeConfig, exists := r.nodeConfigs[resource.Key{Name: nodeName}]
		r.mu.RUnlock()

		if !exists || !isOperatorManaged(nodeConfig) {
			continue
		}

		stillSelected := false
		r.mu.RLock()

		clusterConfigs := make([]*v2alpha1.CiliumNetworkDriverClusterConfig, 0, len(r.clusterConfigs))
		for _, otherConfig := range r.clusterConfigs {
			clusterConfigs = append(clusterConfigs, otherConfig)
		}

		r.mu.RUnlock()

		for _, otherConfig := range clusterConfigs {
			var nodeSelector slim_labels.Selector
			if otherConfig.Spec.NodeSelector == nil {
				nodeSelector = slim_labels.Everything()
			} else {
				selector, err := slim_meta_v1.LabelSelectorAsSelector(otherConfig.Spec.NodeSelector)
				if err != nil {
					continue
				}
				nodeSelector = selector
			}

			r.mu.RLock()
			node, nodeExists := r.ciliumNodes[resource.Key{Name: nodeName}]
			r.mu.RUnlock()

			if !nodeExists {
				continue
			}

			if nodeSelector.Matches(slim_labels.Set(node.Labels)) {
				stillSelected = true
				break
			}
		}

		if !stillSelected {
			err := r.nodeConfigClient.Delete(ctx, nodeName, meta_v1.DeleteOptions{})
			if err != nil && !k8serrors.IsNotFound(err) {
				errs = errors.Join(errs, fmt.Errorf("failed to delete node config for node %s: %w", nodeName, err))
				continue
			}

			r.logger.InfoContext(
				ctx, "Deleted orphaned node config",
				logfields.Node, nodeName,
				logfields.Config, config.Name,
			)
		}
	}

	return errs
}

// cleanupOrphanedNodeConfigs removes operator-managed NodeConfig resources for nodes
// that no longer exist or are not selected by any ClusterConfig.
func (r *ConfigReconciler) cleanupOrphanedNodeConfigs(ctx context.Context) error {
	var errs error

	expectedNodes := sets.New[string]()

	r.mu.RLock()

	configs := make([]*v2alpha1.CiliumNetworkDriverClusterConfig, 0, len(r.clusterConfigs))
	for _, config := range r.clusterConfigs {
		configs = append(configs, config)
	}

	nodes := make([]*v2.CiliumNode, 0, len(r.ciliumNodes))

	for _, node := range r.ciliumNodes {
		nodes = append(nodes, node)
	}

	r.mu.RUnlock()

	for _, config := range configs {
		var nodeSelector slim_labels.Selector
		if config.Spec.NodeSelector == nil {
			nodeSelector = slim_labels.Everything()
		} else {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(config.Spec.NodeSelector)
			if err != nil {
				continue
			}

			nodeSelector = selector
		}

		for _, node := range nodes {
			if nodeSelector.Matches(slim_labels.Set(node.Labels)) {
				expectedNodes.Insert(node.Name)
			}
		}
	}

	r.mu.RLock()

	nodeConfigs := make([]*v2alpha1.CiliumNetworkDriverNodeConfig, 0, len(r.nodeConfigs))
	for _, nc := range r.nodeConfigs {
		nodeConfigs = append(nodeConfigs, nc)
	}

	r.mu.RUnlock()

	for _, nodeConfig := range nodeConfigs {
		if !isOperatorManaged(nodeConfig) {
			continue
		}

		r.mu.RLock()
		_, nodeExists := r.ciliumNodes[resource.Key{Name: nodeConfig.Name}]
		r.mu.RUnlock()

		if !nodeExists || !expectedNodes.Has(nodeConfig.Name) {
			err := r.nodeConfigClient.Delete(ctx, nodeConfig.Name, meta_v1.DeleteOptions{})
			if err != nil && !k8serrors.IsNotFound(err) {
				errs = errors.Join(errs, fmt.Errorf("failed to delete orphaned node config for node %s: %w", nodeConfig.Name, err))
				continue
			}

			r.logger.InfoContext(
				ctx, "Deleted orphaned node config during cleanup",
				logfields.Node, nodeConfig.Name,
			)
		}
	}

	return errs
}

// isOperatorManaged returns true if the NodeConfig resource is managed by the operator.
func isOperatorManaged(nodeConfig *v2alpha1.CiliumNetworkDriverNodeConfig) bool {
	return nodeConfig.Status.ManagedBy == ManagedByOperator
}

// isRetryableError classifies errors as retryable based on their type.
func isRetryableError(err error) bool {
	return k8serrors.IsAlreadyExists(err) ||
		k8serrors.IsConflict(err) ||
		k8serrors.IsNotFound(err) ||
		(k8serrors.IsForbidden(err) && k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause))
}

// ConflictError represents a configuration conflict where multiple ClusterConfigs
// are trying to manage the same NodeConfig.
type ConflictError struct {
	NodeName     string
	OldConfig    string
	NewConfig    string
	ConflictType string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("conflict for node %s: already assigned by %s (attempting: %s, type: %s)",
		e.NodeName, e.OldConfig, e.NewConfig, e.ConflictType)
}

// updateClusterConfigStatus updates the ClusterConfig status with conflict information.
func (r *ConfigReconciler) updateClusterConfigStatus(ctx context.Context, config *v2alpha1.CiliumNetworkDriverClusterConfig, conflicts []*ConflictError) error {
	updatedConfig := config.DeepCopy()

	// Build conflict message
	nodeNames := make([]string, 0, len(conflicts))
	conflictDetails := make(map[string]string)
	for _, c := range conflicts {
		nodeNames = append(nodeNames, c.NodeName)
		conflictDetails[c.NodeName] = fmt.Sprintf("%s (previous: %s)", c.ConflictType, c.OldConfig)
	}

	conflictMsg := fmt.Sprintf("Configuration conflicts for nodes: %s", strings.Join(nodeNames, ", "))

	// Add or update Conflict condition
	condition := meta_v1.Condition{
		Type:               "Conflict",
		Status:             meta_v1.ConditionTrue,
		Reason:             "MultipleClusterConfigsMatch",
		Message:            conflictMsg,
		LastTransitionTime: meta_v1.Now(),
	}

	// Find and update or append condition
	found := false
	for i, c := range updatedConfig.Status.Conditions {
		if c.Type == "Conflict" {
			// Only update if the message changed
			if c.Message != conflictMsg {
				updatedConfig.Status.Conditions[i] = condition
			} else {
				// No change needed
				return nil
			}
			found = true
			break
		}
	}
	if !found {
		updatedConfig.Status.Conditions = append(updatedConfig.Status.Conditions, condition)
	}

	// Sort conditions for stable ordering (pattern from bgp/cluster.go)
	slices.SortStableFunc(updatedConfig.Status.Conditions, func(a, b meta_v1.Condition) int {
		return strings.Compare(a.Type, b.Type)
	})

	_, err := r.clusterConfigClient.UpdateStatus(ctx, updatedConfig, meta_v1.UpdateOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("failed to update cluster config status: %w", err)
	}

	return nil
}

// clearClusterConfigConflicts removes the Conflict condition from ClusterConfig status.
func (r *ConfigReconciler) clearClusterConfigConflicts(ctx context.Context, config *v2alpha1.CiliumNetworkDriverClusterConfig) error {
	// Check if there's a Conflict condition to clear
	hasConflict := false
	for _, c := range config.Status.Conditions {
		if c.Type == "Conflict" && c.Status == meta_v1.ConditionTrue {
			hasConflict = true
			break
		}
	}

	if !hasConflict {
		// No conflict condition to clear
		return nil
	}

	updatedConfig := config.DeepCopy()

	// Remove Conflict condition
	newConditions := make([]meta_v1.Condition, 0, len(updatedConfig.Status.Conditions))
	for _, c := range updatedConfig.Status.Conditions {
		if c.Type != "Conflict" {
			newConditions = append(newConditions, c)
		}
	}
	updatedConfig.Status.Conditions = newConditions

	_, err := r.clusterConfigClient.UpdateStatus(ctx, updatedConfig, meta_v1.UpdateOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("failed to clear cluster config conflict status: %w", err)
	}

	return nil
}
