// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"sync"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/endpointmanager"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/node"
)

const (
	statusUpdateMaxRetries = 3
)

// appliedEndpoint tracks the last-applied BPF state for a given CIDR.
type appliedEndpoint struct {
	tunnelEndpoint string
	mac            string
	configName     string // which CiliumVTEPConfig this came from
}

// desiredEP represents an endpoint from a matching config, keyed by normalized CIDR string.
type desiredEP struct {
	endpoint   cilium_api_v2.VTEPEndpoint
	configName string
	cidrStr    string // original CIDR string from CRD spec
}

// pendingStatusUpdate holds a status update to be applied after releasing the mutex.
type pendingStatusUpdate struct {
	config         *cilium_api_v2.CiliumVTEPConfig
	endpointErrors map[string]error
	ready          bool
	message        string
	isFullStatus   bool
}

// VTEPReconciler watches CiliumVTEPConfig CRDs and reconciles changes to the BPF map.
// It supports multiple CiliumVTEPConfig objects with nodeSelector-based filtering.
type VTEPReconciler struct {
	logger          *slog.Logger
	vtepMap         vtep.Map
	clientset       client.Clientset
	resource        resource.Resource[*cilium_api_v2.CiliumVTEPConfig]
	manager         *vtepManager
	endpointManager endpointmanager.EndpointManager

	db             *statedb.DB
	localNodeTable statedb.Table[*node.LocalNode]

	// mu protects allConfigs, lastApplied, and BPF map operations.
	mu sync.Mutex

	// allConfigs stores all known CiliumVTEPConfig objects by name.
	allConfigs map[string]*cilium_api_v2.CiliumVTEPConfig

	// lastApplied tracks the last BPF state, keyed by normalized CIDR string
	// (e.g. "10.1.1.0/24"). This matches the LPM trie key: {prefixlen, network_ip}.
	lastApplied map[string]appliedEndpoint

	// initialCleanupDone tracks whether the first-run BPF map cleanup has been done.
	initialCleanupDone bool

	// crdSynced is set after the resource.Sync event is received.
	crdSynced bool
}

// vtepReconcilerParams contains parameters for creating a VTEPReconciler.
type vtepReconcilerParams struct {
	Logger          *slog.Logger
	VTEPMap         vtep.Map
	Clientset       client.Clientset
	Resource        resource.Resource[*cilium_api_v2.CiliumVTEPConfig]
	Manager         *vtepManager
	EndpointManager endpointmanager.EndpointManager
	DB              *statedb.DB
	LocalNodeTable  statedb.Table[*node.LocalNode]
}

// newVTEPReconciler creates a new VTEPReconciler instance.
func newVTEPReconciler(params vtepReconcilerParams) *VTEPReconciler {
	return &VTEPReconciler{
		logger:          params.Logger,
		vtepMap:         params.VTEPMap,
		clientset:       params.Clientset,
		resource:        params.Resource,
		manager:         params.Manager,
		endpointManager: params.EndpointManager,
		db:              params.DB,
		localNodeTable:  params.LocalNodeTable,
		allConfigs:      make(map[string]*cilium_api_v2.CiliumVTEPConfig),
		lastApplied:     make(map[string]appliedEndpoint),
	}
}

// Run starts the reconciler loop that watches for CiliumVTEPConfig changes.
func (r *VTEPReconciler) Run(ctx context.Context) error {
	if r.resource == nil {
		r.logger.Debug("CiliumVTEPConfig resource not available, reconciler not starting")
		return nil
	}

	r.logger.Info("Starting VTEP CRD reconciler")

	for event := range r.resource.Events(ctx) {
		var result syncResult
		switch event.Kind {
		case resource.Sync:
			r.mu.Lock()
			r.crdSynced = true
			result = r.syncDesiredStateLocked(ctx)
			r.mu.Unlock()
			r.applyPendingStatusUpdates(ctx, result.pendingUpdates)
			r.logger.Debug("VTEP CRD resource synced")
		case resource.Upsert:
			r.mu.Lock()
			r.allConfigs[event.Object.Name] = event.Object.DeepCopy()
			result = r.syncDesiredStateLocked(ctx)
			r.mu.Unlock()
			r.applyPendingStatusUpdates(ctx, result.pendingUpdates)
		case resource.Delete:
			r.mu.Lock()
			delete(r.allConfigs, event.Object.Name)
			result = r.syncDesiredStateLocked(ctx)
			r.mu.Unlock()
			r.applyPendingStatusUpdates(ctx, result.pendingUpdates)
		}
		event.Done(result.err)
	}

	return nil
}

// watchNodeLabels watches for node label changes and triggers reconciliation.
func (r *VTEPReconciler) watchNodeLabels(ctx context.Context, _ cell.Health) error {
	var oldLabels map[string]string
	for {
		txn := r.db.ReadTxn()
		localNode, _, watch, found := r.localNodeTable.GetWatch(txn, node.LocalNodeQuery)
		if found {
			newLabels := localNode.Labels
			if oldLabels == nil || !maps.Equal(newLabels, oldLabels) {
				r.logger.Debug("Node labels changed, re-evaluating VTEP configs",
					"old", oldLabels,
					"new", newLabels)
				if err := r.syncDesiredState(ctx); err != nil {
					r.logger.Warn("syncDesiredState failed after label change, will retry",
						logfields.Error, err)
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(5 * time.Second):
						continue
					}
				}
				oldLabels = newLabels
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}

// getLocalNodeLabels reads the current local node labels from statedb.
func (r *VTEPReconciler) getLocalNodeLabels() map[string]string {
	if r.db == nil || r.localNodeTable == nil {
		return nil
	}
	txn := r.db.ReadTxn()
	localNode, _, found := r.localNodeTable.Get(txn, node.LocalNodeQuery)
	if !found {
		return nil
	}
	return localNode.Labels
}

// configMatchesNode checks if a CiliumVTEPConfig's nodeSelector matches the given node labels.
// A nil or empty nodeSelector matches all nodes.
func configMatchesNode(config *cilium_api_v2.CiliumVTEPConfig, nodeLabels map[string]string) (bool, error) {
	if config.Spec.NodeSelector == nil {
		return true, nil
	}

	selector, err := slim_metav1.LabelSelectorAsSelector(config.Spec.NodeSelector)
	if err != nil {
		return false, fmt.Errorf("invalid nodeSelector: %w", err)
	}

	return selector.Matches(labels.Set(nodeLabels)), nil
}

// syncDesiredState acquires the mutex and reconciles BPF state.
//
// Status updates are intentionally deferred until after the mutex is released.
// syncDesiredStateLocked collects pending updates into result.pendingUpdates
// using deep copies of config objects, so they are safe to use outside the lock.
// This avoids holding the mutex during potentially slow API server calls
// (UpdateStatus + retry-with-refetch), while still ensuring the BPF state
// and lastApplied tracking remain consistent under the lock.
func (r *VTEPReconciler) syncDesiredState(ctx context.Context) error {
	r.mu.Lock()
	result := r.syncDesiredStateLocked(ctx)
	r.mu.Unlock()
	r.applyPendingStatusUpdates(ctx, result.pendingUpdates)
	return result.err
}

// syncResult holds the output of syncDesiredStateLocked.
type syncResult struct {
	err            error
	pendingUpdates []pendingStatusUpdate
}

// syncDesiredStateLocked is the single reconciliation point. Caller must hold r.mu.
// It:
// 1. Reads local node labels
// 2. Filters configs by nodeSelector
// 3. Detects CIDR conflicts across matching configs
// 4. Diffs against lastApplied and updates BPF map
// 5. Returns syncResult with pending status updates
func (r *VTEPReconciler) syncDesiredStateLocked(ctx context.Context) syncResult {
	nodeLabels := r.getLocalNodeLabels()

	// desired is keyed by the normalized CIDR string (e.g. "10.1.1.0/24").
	// cidr.ParseCIDR normalizes host bits so "10.1.1.5/24" → "10.1.1.0/24".
	// This string maps 1:1 to the LPM trie key {prefixlen=24, ip=10.1.1.0}.
	desired := make(map[string]desiredEP)
	conflicts := make(map[string][]string)            // cidr string -> conflicting config names
	configErrors := make(map[string]map[string]error) // configName -> endpointName -> error
	matchingConfigs := make(map[string]bool)

	var pendingUpdates []pendingStatusUpdate

	for name, config := range r.allConfigs {
		matches, err := configMatchesNode(config, nodeLabels)
		if err != nil {
			r.logger.Warn("Invalid nodeSelector in CiliumVTEPConfig, skipping",
				logfields.Name, name,
				logfields.Error, err)
			if configErrors[name] == nil {
				configErrors[name] = make(map[string]error)
			}
			configErrors[name]["nodeSelector"] = err
			pendingUpdates = append(pendingUpdates, pendingStatusUpdate{
				config:  config.DeepCopy(),
				ready:   false,
				message: fmt.Sprintf("invalid nodeSelector: %v", err),
			})
			continue
		}

		if !matches {
			r.logger.Debug("CiliumVTEPConfig does not match this node's labels, skipping",
				logfields.Name, name)
			continue
		}

		matchingConfigs[name] = true

		if err := r.validateConfig(config); err != nil {
			r.logger.Warn("Invalid CiliumVTEPConfig, skipping",
				logfields.Name, name,
				logfields.Error, err)
			if configErrors[name] == nil {
				configErrors[name] = make(map[string]error)
			}
			configErrors[name]["validation"] = err
			pendingUpdates = append(pendingUpdates, pendingStatusUpdate{
				config:  config.DeepCopy(),
				ready:   false,
				message: fmt.Sprintf("invalid config: %v", err),
			})
			continue
		}

		for _, ep := range config.Spec.Endpoints {
			externalCIDR, err := cidr.ParseCIDR(ep.CIDR)
			if err != nil {
				if configErrors[name] == nil {
					configErrors[name] = make(map[string]error)
				}
				configErrors[name][ep.Name] = fmt.Errorf("invalid CIDR %s: %w", ep.CIDR, err)
				continue
			}
			// Normalized CIDR string is the BPF LPM key: {prefixlen, network_ip}.
			cidrKey := externalCIDR.String()

			if existing, ok := desired[cidrKey]; ok && existing.configName != name {
				conflicts[cidrKey] = append(conflicts[cidrKey], name)
				if len(conflicts[cidrKey]) == 1 {
					conflicts[cidrKey] = append([]string{existing.configName}, conflicts[cidrKey]...)
				}
			} else if !ok {
				desired[cidrKey] = desiredEP{endpoint: ep, configName: name, cidrStr: ep.CIDR}
			}
		}
	}

	// Remove conflicting CIDRs and report errors.
	for cidrKey, configNames := range conflicts {
		existingEP := desired[cidrKey]
		delete(desired, cidrKey)
		errMsg := fmt.Sprintf("CIDR %s conflicts across configs: %v", cidrKey, configNames)
		r.logger.Error(errMsg)
		for _, cfgName := range configNames {
			if configErrors[cfgName] == nil {
				configErrors[cfgName] = make(map[string]error)
			}
			epName := ""
			if cfg, ok := r.allConfigs[cfgName]; ok {
				for _, ep := range cfg.Spec.Endpoints {
					parsedCIDR, err := cidr.ParseCIDR(ep.CIDR)
					if err == nil && parsedCIDR.String() == cidrKey {
						epName = ep.Name
						break
					}
				}
			}
			if cfgName == existingEP.configName {
				epName = existingEP.endpoint.Name
			}
			configErrors[cfgName][epName] = fmt.Errorf("CIDR %s conflicts with other matching config(s)", cidrKey)
		}
	}

	// Check total endpoints count.
	if len(desired) > vtep.MaxEntries {
		errMsg := fmt.Sprintf("total endpoints across matching configs (%d) exceeds maximum (%d)", len(desired), vtep.MaxEntries)
		r.logger.Error(errMsg)
		for name := range matchingConfigs {
			pendingUpdates = append(pendingUpdates, pendingStatusUpdate{
				config:  r.allConfigs[name].DeepCopy(),
				ready:   false,
				message: errMsg,
			})
		}
		return syncResult{
			err:            fmt.Errorf("%s", errMsg),
			pendingUpdates: pendingUpdates,
		}
	}

	// Apply/update desired endpoints (add before delete to avoid traffic drops).
	for cidrKey, dep := range desired {
		ep := dep.endpoint

		if existing, ok := r.lastApplied[cidrKey]; ok &&
			existing.tunnelEndpoint == ep.TunnelEndpoint &&
			existing.mac == ep.MAC &&
			existing.configName == dep.configName {
			continue
		}

		if err := r.applyConnection(dep.cidrStr, ep.TunnelEndpoint, ep.MAC); err != nil {
			if configErrors[dep.configName] == nil {
				configErrors[dep.configName] = make(map[string]error)
			}
			configErrors[dep.configName][ep.Name] = err
			r.logger.Error("Failed to apply VTEP endpoint",
				logfields.Name, ep.Name,
				"config", dep.configName,
				logfields.Error, err)
		} else {
			r.lastApplied[cidrKey] = appliedEndpoint{
				tunnelEndpoint: ep.TunnelEndpoint,
				mac:            ep.MAC,
				configName:     dep.configName,
			}
			r.logger.Info("Successfully applied VTEP endpoint",
				logfields.Name, ep.Name,
				"config", dep.configName,
				"tunnelEndpoint", ep.TunnelEndpoint,
				"cidr", dep.cidrStr)
		}
	}

	// On first reconcile after CRD sync, clean up stale BPF map entries
	// left from a previous agent run.
	if !r.initialCleanupDone && r.crdSynced {
		r.cleanupStaleBPFEntries(desired)
		r.initialCleanupDone = true
	}

	// Delete stale entries from lastApplied that are no longer desired.
	for cidrKey, applied := range r.lastApplied {
		if _, stillDesired := desired[cidrKey]; !stillDesired {
			parsedCIDR, err := cidr.ParseCIDR(cidrKey)
			if err != nil {
				r.logger.Warn("Invalid CIDR key in lastApplied, skipping delete",
					"cidr", cidrKey)
				continue
			}
			if err := r.vtepMap.Delete(parsedCIDR); err != nil {
				r.logger.Warn("Failed to delete stale VTEP BPF entry, will retry on next sync",
					"cidr", cidrKey,
					logfields.Error, err)
				continue
			}
			r.logger.Info("Deleted stale VTEP BPF entry",
				"cidr", cidrKey,
				"previousConfig", applied.configName)
			delete(r.lastApplied, cidrKey)
		}
	}

	// Update manager config with successfully-applied endpoints for route management.
	if r.manager != nil {
		mgConfig := vtepManagerConfig{}
		for cidrKey, dep := range desired {
			if _, applied := r.lastApplied[cidrKey]; !applied {
				continue
			}
			externalCIDR, err := cidr.ParseCIDR(dep.cidrStr)
			if err != nil {
				continue
			}
			mgConfig.vtepCIDRs = append(mgConfig.vtepCIDRs, externalCIDR)
		}
		r.manager.config = mgConfig

		if err := r.manager.setupRouteToVTEPCidr(); err != nil {
			r.logger.Error("Failed to setup VTEP routes", logfields.Error, err)
		}
	}

	// Collect per-config status updates.
	var syncErr error
	for name := range matchingConfigs {
		config := r.allConfigs[name]
		epErrors := configErrors[name]
		pendingUpdates = append(pendingUpdates, pendingStatusUpdate{
			config:         config.DeepCopy(),
			endpointErrors: epErrors,
			isFullStatus:   true,
		})
		if len(epErrors) > 0 && syncErr == nil {
			syncErr = fmt.Errorf("sync errors for config %s", name)
		}
	}

	return syncResult{err: syncErr, pendingUpdates: pendingUpdates}
}

// applyPendingStatusUpdates writes deferred CRD status updates.
func (r *VTEPReconciler) applyPendingStatusUpdates(ctx context.Context, updates []pendingStatusUpdate) {
	for _, u := range updates {
		if u.isFullStatus {
			r.updateFullStatus(ctx, u.config, u.endpointErrors)
		} else {
			r.updateStatus(ctx, u.config, u.ready, u.message)
		}
	}
}

// cleanupStaleBPFEntries removes BPF map entries not present in desired.
// Called on first syncDesiredState to handle agent restarts.
func (r *VTEPReconciler) cleanupStaleBPFEntries(desiredKeys map[string]desiredEP) {
	entries, err := r.vtepMap.List()
	if err != nil {
		r.logger.Warn("Failed to list BPF map entries for stale cleanup",
			logfields.Error, err)
		return
	}

	for _, entry := range entries {
		// Normalize to 4-byte IPv4 form before reconstruction.
		// entry.CIDR may be a 16-byte IPv4-mapped address (e.g. ::ffff:10.1.1.0),
		// which would make net.IPNet.String() produce "::ffff:10.1.1.0/24" instead
		// of "10.1.1.0/24", breaking the match against desiredKeys.
		ipv4 := entry.CIDR.To4()
		if ipv4 == nil {
			r.logger.Warn("Non-IPv4 address in VTEP BPF map, skipping",
				"cidr", entry.CIDR)
			continue
		}
		// Reconstruct the normalized CIDR string used as the map key.
		ipNet := &net.IPNet{
			IP:   ipv4,
			Mask: net.CIDRMask(entry.PrefixLen, 32),
		}
		entryKey := ipNet.String() // e.g. "10.1.1.0/24"

		if _, ok := desiredKeys[entryKey]; !ok {
			parsedCIDR, err := cidr.ParseCIDR(entryKey)
			if err != nil {
				r.logger.Warn("Failed to parse stale BPF entry CIDR on startup",
					"cidr", entryKey,
					logfields.Error, err)
				continue
			}
			if err := r.vtepMap.Delete(parsedCIDR); err != nil {
				r.logger.Warn("Failed to delete stale BPF map entry on startup",
					"cidr", entryKey,
					logfields.Error, err)
			} else {
				r.logger.Info("Cleaned up stale BPF map entry on startup",
					"cidr", entryKey)
			}
		}
	}
}

// applyConnection writes a single tunnel endpoint + MAC to the BPF map for a given CIDR.
func (r *VTEPReconciler) applyConnection(cidrStr string, tunnelEndpoint string, macAddr string) error {
	tunnelEP := net.ParseIP(tunnelEndpoint)
	if tunnelEP == nil {
		return fmt.Errorf("invalid tunnel endpoint IP: %s", tunnelEndpoint)
	}
	if tunnelEP.To4() == nil {
		return fmt.Errorf("tunnel endpoint must be IPv4: %s", tunnelEndpoint)
	}

	externalCIDR, err := cidr.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	externalMAC, err := mac.ParseMAC(macAddr)
	if err != nil {
		return fmt.Errorf("invalid MAC: %w", err)
	}

	if err := r.vtepMap.Update(externalCIDR, tunnelEP, externalMAC); err != nil {
		return fmt.Errorf("failed to update BPF map: %w", err)
	}

	return nil
}

// validateConfig validates a CiliumVTEPConfig.
func (r *VTEPReconciler) validateConfig(config *cilium_api_v2.CiliumVTEPConfig) error {
	if len(config.Spec.Endpoints) == 0 {
		return fmt.Errorf("at least one endpoint is required")
	}

	if len(config.Spec.Endpoints) > vtep.MaxEntries {
		return fmt.Errorf("maximum %d endpoints allowed, got %d", vtep.MaxEntries, len(config.Spec.Endpoints))
	}

	names := make(map[string]bool)
	// cidrKeys maps normalized CIDR string → original CIDR for duplicate detection.
	// cidr.ParseCIDR normalizes host bits: "10.1.1.5/24" and "10.1.1.0/24" both
	// resolve to "10.1.1.0/24" and are correctly flagged as duplicates.
	cidrKeys := make(map[string]string)

	for _, ep := range config.Spec.Endpoints {
		if names[ep.Name] {
			return fmt.Errorf("duplicate endpoint name: %s", ep.Name)
		}
		names[ep.Name] = true

		tunnelIP := net.ParseIP(ep.TunnelEndpoint)
		if tunnelIP == nil {
			return fmt.Errorf("invalid tunnel endpoint IP for %s: %s", ep.Name, ep.TunnelEndpoint)
		}
		if tunnelIP.To4() == nil {
			return fmt.Errorf("tunnel endpoint must be IPv4 for %s: %s", ep.Name, ep.TunnelEndpoint)
		}

		externalCIDR, err := cidr.ParseCIDR(ep.CIDR)
		if err != nil {
			return fmt.Errorf("invalid CIDR for %s: %s", ep.Name, ep.CIDR)
		}
		if externalCIDR.IP.To4() == nil {
			return fmt.Errorf("CIDR must be IPv4 for %s: %s (VTEP is IPv4-only)", ep.Name, ep.CIDR)
		}

		normalizedCIDR := externalCIDR.String()
		if existingCIDR, ok := cidrKeys[normalizedCIDR]; ok {
			return fmt.Errorf("CIDR %s normalizes to the same entry as %s (endpoint %s)",
				ep.CIDR, existingCIDR, ep.Name)
		}
		cidrKeys[normalizedCIDR] = ep.CIDR

		if _, err := mac.ParseMAC(ep.MAC); err != nil {
			return fmt.Errorf("invalid MAC for %s: %s", ep.Name, ep.MAC)
		}
	}

	return nil
}

// updateStatus updates the status with a simple ready/not-ready condition.
func (r *VTEPReconciler) updateStatus(ctx context.Context, config *cilium_api_v2.CiliumVTEPConfig, ready bool, message string) {
	if r.clientset == nil || !r.clientset.IsEnabled() {
		return
	}

	configCopy := config.DeepCopy()
	configCopy.Status.EndpointCount = int32(len(config.Spec.Endpoints))

	now := metav1.Now()
	readyCondition := metav1.Condition{
		Type:               cilium_api_v2.VTEPConditionReady,
		ObservedGeneration: config.Generation,
	}

	if ready {
		readyCondition.Status = metav1.ConditionTrue
		readyCondition.Reason = "Synced"
		readyCondition.Message = message
		if message == "" {
			readyCondition.Message = "All endpoints synced to BPF map"
		}
	} else {
		readyCondition.Status = metav1.ConditionFalse
		readyCondition.Reason = "SyncFailed"
		readyCondition.Message = message
	}
	setCondition(&configCopy.Status.Conditions, readyCondition, now)

	r.updateStatusWithRetry(ctx, configCopy)
}

// updateFullStatus updates the CRD status with per-endpoint sync information.
func (r *VTEPReconciler) updateFullStatus(ctx context.Context, config *cilium_api_v2.CiliumVTEPConfig, endpointErrors map[string]error) {
	if r.clientset == nil || !r.clientset.IsEnabled() {
		return
	}

	endpointStatuses := make([]cilium_api_v2.VTEPEndpointStatus, 0, len(config.Spec.Endpoints))
	allSynced := len(endpointErrors) == 0

	for _, ep := range config.Spec.Endpoints {
		status := cilium_api_v2.VTEPEndpointStatus{
			Name:   ep.Name,
			Synced: true,
		}
		if err, ok := endpointErrors[ep.Name]; ok {
			status.Synced = false
			status.Error = err.Error()
		} else {
			now := metav1.Now()
			status.LastSyncTime = &now
		}
		endpointStatuses = append(endpointStatuses, status)
	}

	configCopy := config.DeepCopy()
	configCopy.Status.EndpointCount = int32(len(config.Spec.Endpoints))
	configCopy.Status.EndpointStatuses = endpointStatuses

	now := metav1.Now()
	readyCondition := metav1.Condition{
		Type:               cilium_api_v2.VTEPConditionReady,
		ObservedGeneration: config.Generation,
	}
	if allSynced {
		readyCondition.Status = metav1.ConditionTrue
		readyCondition.Reason = "Synced"
		readyCondition.Message = "All endpoints synced to BPF map"
	} else {
		readyCondition.Status = metav1.ConditionFalse
		readyCondition.Reason = "SyncFailed"
		readyCondition.Message = "Some endpoints failed to sync"
	}
	setCondition(&configCopy.Status.Conditions, readyCondition, now)

	r.updateStatusWithRetry(ctx, configCopy)
}

// updateStatusWithRetry writes the CRD status with retry on conflict.
func (r *VTEPReconciler) updateStatusWithRetry(ctx context.Context, configCopy *cilium_api_v2.CiliumVTEPConfig) {
	for i := 0; i < statusUpdateMaxRetries; i++ {
		_, err := r.clientset.CiliumV2().CiliumVTEPConfigs().UpdateStatus(ctx, configCopy, metav1.UpdateOptions{})
		if err == nil {
			return
		}
		if !k8serrors.IsConflict(err) {
			r.logger.Error("Failed to update CiliumVTEPConfig status",
				logfields.Name, configCopy.Name,
				logfields.Error, err)
			return
		}
		r.logger.Debug("Status update conflict, retrying",
			logfields.Name, configCopy.Name,
			"attempt", i+1)

		fresh, err := r.clientset.CiliumV2().CiliumVTEPConfigs().Get(ctx, configCopy.Name, metav1.GetOptions{})
		if err != nil {
			r.logger.Error("Failed to re-fetch CiliumVTEPConfig for status retry",
				logfields.Name, configCopy.Name,
				logfields.Error, err)
			return
		}
		fresh.Status = configCopy.Status
		configCopy = fresh
	}
}

// setCondition updates or adds a condition in the conditions slice.
func setCondition(conditions *[]metav1.Condition, newCondition metav1.Condition, now metav1.Time) {
	for i, cond := range *conditions {
		if cond.Type == newCondition.Type {
			if cond.Status != newCondition.Status {
				newCondition.LastTransitionTime = now
			} else {
				newCondition.LastTransitionTime = cond.LastTransitionTime
			}
			(*conditions)[i] = newCondition
			return
		}
	}
	newCondition.LastTransitionTime = now
	*conditions = append(*conditions, newCondition)
}
