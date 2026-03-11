// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/cidr"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/vtep"
)

const (
	statusUpdateMaxRetries = 3

	// AnnotationResetFailover triggers a manual failover reset when set to "true".
	// All endpoints are switched back to primary, cooldown timers and counters are cleared.
	// The annotation is removed after processing.
	AnnotationResetFailover = "vtep.cilium.io/reset-failover"
)

// VTEPReconciler watches CiliumVTEPConfig CRD and reconciles changes to the BPF map.
type VTEPReconciler struct {
	logger        *slog.Logger
	vtepMap       vtep.Map
	clientset     client.Clientset
	resource      resource.Resource[*cilium_api_v2.CiliumVTEPConfig]
	manager       *vtepManager
	healthMonitor *vtepHealthMonitor
	failoverCh    chan failoverEvent

	// lastConfig tracks the last applied config for change detection
	lastConfig *cilium_api_v2.CiliumVTEPConfig
}

// vtepReconcilerParams contains parameters for creating a VTEPReconciler.
type vtepReconcilerParams struct {
	Logger        *slog.Logger
	VTEPMap       vtep.Map
	Clientset     client.Clientset
	Resource      resource.Resource[*cilium_api_v2.CiliumVTEPConfig]
	Manager       *vtepManager
	HealthMonitor *vtepHealthMonitor
	FailoverCh    chan failoverEvent
}

// newVTEPReconciler creates a new VTEPReconciler instance.
func newVTEPReconciler(params vtepReconcilerParams) *VTEPReconciler {
	return &VTEPReconciler{
		logger:        params.Logger,
		vtepMap:       params.VTEPMap,
		clientset:     params.Clientset,
		resource:      params.Resource,
		manager:       params.Manager,
		healthMonitor: params.HealthMonitor,
		failoverCh:    params.FailoverCh,
	}
}

// Run starts the reconciler loop that watches for CiliumVTEPConfig changes.
func (r *VTEPReconciler) Run(ctx context.Context) error {
	if r.resource == nil {
		r.logger.Debug("CiliumVTEPConfig resource not available, reconciler not starting")
		return nil
	}

	r.logger.Info("Starting VTEP CRD reconciler")

	events := r.resource.Events(ctx)

	for {
		select {
		case event, ok := <-events:
			if !ok {
				return nil
			}
			var err error
			switch event.Kind {
			case resource.Sync:
				r.logger.Debug("VTEP CRD resource synced")
			case resource.Upsert:
				if err = r.reconcileUpsert(ctx, event.Object); err != nil {
					r.logger.Error("Failed to reconcile VTEP config upsert",
						logfields.Error, err,
						logfields.Name, event.Object.Name)
				}
			case resource.Delete:
				if err = r.reconcileDelete(ctx, event.Object); err != nil {
					r.logger.Error("Failed to reconcile VTEP config delete",
						logfields.Error, err,
						logfields.Name, event.Object.Name)
				}
			}
			event.Done(err)

		case foEvent := <-r.failoverCh:
			r.processFailoverEvent(ctx, foEvent)
		}
	}
}

// processFailoverEvent handles a failover event from the health monitor.
// It updates the BPF map to point to the new active connection.
func (r *VTEPReconciler) processFailoverEvent(ctx context.Context, event failoverEvent) {
	if r.lastConfig == nil {
		r.logger.Warn("Failover event received but no config available",
			logfields.Name, event.endpointName)
		return
	}

	// Find the endpoint in the config
	for _, ep := range r.lastConfig.Spec.Endpoints {
		if ep.Name != event.endpointName || ep.Standby == nil {
			continue
		}

		var tunnelEP string
		var macAddr string
		switch event.newRole {
		case "primary":
			tunnelEP = ep.TunnelEndpoint
			macAddr = ep.MAC
		case "standby":
			tunnelEP = ep.Standby.TunnelEndpoint
			macAddr = ep.Standby.MAC
		default:
			r.logger.Error("Unknown failover role", "role", event.newRole)
			return
		}

		if err := r.applyConnection(ep.CIDR, tunnelEP, macAddr); err != nil {
			r.logger.Error("Failed to apply failover",
				logfields.Name, ep.Name,
				"newRole", event.newRole,
				logfields.Error, err)
			return
		}

		r.logger.Info("Failover applied successfully",
			logfields.Name, ep.Name,
			"newRole", event.newRole,
			"tunnelEndpoint", tunnelEP)

		// Update status to reflect failover
		r.updateFullStatus(ctx, r.lastConfig, nil)
		return
	}

	r.logger.Warn("Failover event for unknown endpoint",
		logfields.Name, event.endpointName)
}

// resetFailover resets all endpoints back to primary, clears cooldown timers
// and failover counters, updates BPF maps, and removes the reset annotation.
func (r *VTEPReconciler) resetFailover(ctx context.Context, config *cilium_api_v2.CiliumVTEPConfig) {
	// Reset health monitor state (roles, counters, cooldowns)
	if r.healthMonitor != nil {
		r.healthMonitor.resetAllState()
	}

	// Re-apply all endpoints as primary
	for _, ep := range config.Spec.Endpoints {
		if err := r.applyConnection(ep.CIDR, ep.TunnelEndpoint, ep.MAC); err != nil {
			r.logger.Error("Failed to reset endpoint to primary",
				logfields.Name, ep.Name,
				logfields.Error, err)
		} else {
			r.logger.Info("Reset endpoint to primary",
				logfields.Name, ep.Name)
		}
	}

	// Remove the annotation
	configCopy := config.DeepCopy()
	delete(configCopy.Annotations, AnnotationResetFailover)
	_, err := r.clientset.CiliumV2().CiliumVTEPConfigs().Update(ctx, configCopy, metav1.UpdateOptions{})
	if err != nil {
		r.logger.Error("Failed to remove reset-failover annotation", logfields.Error, err)
	}
}

// reconcileUpsert handles creation or update of a CiliumVTEPConfig.
func (r *VTEPReconciler) reconcileUpsert(ctx context.Context, config *cilium_api_v2.CiliumVTEPConfig) error {
	r.logger.Info("Reconciling VTEP config upsert",
		logfields.Name, config.Name,
		"endpointCount", len(config.Spec.Endpoints))

	// Validate the configuration
	if err := r.validateConfig(config); err != nil {
		r.updateStatus(ctx, config, false, err.Error())
		return fmt.Errorf("invalid VTEP config: %w", err)
	}

	// Check for manual failover reset annotation
	if config.Annotations[AnnotationResetFailover] == "true" {
		r.logger.Info("Manual failover reset triggered via annotation")
		r.resetFailover(ctx, config)
	}

	// Clean up stale BPF map entries for CIDRs that were removed or changed
	if r.lastConfig != nil {
		newCIDRs := make(map[string]bool, len(config.Spec.Endpoints))
		for _, ep := range config.Spec.Endpoints {
			newCIDRs[ep.CIDR] = true
		}
		for _, prevEP := range r.lastConfig.Spec.Endpoints {
			if !newCIDRs[prevEP.CIDR] {
				// This CIDR is no longer in the config — delete from BPF map
				externalCIDR, err := cidr.ParseCIDR(prevEP.CIDR)
				if err == nil {
					if err := r.vtepMap.DeleteByCIDR(externalCIDR.IP); err != nil {
						r.logger.Warn("Failed to delete stale VTEP BPF entry",
							"cidr", prevEP.CIDR,
							logfields.Error, err)
					} else {
						r.logger.Info("Deleted stale VTEP BPF entry for removed CIDR",
							"cidr", prevEP.CIDR)
					}
				}
			}
		}
	}

	// Apply each endpoint with config-change awareness
	var syncErrors []string
	for _, ep := range config.Spec.Endpoints {
		if err := r.applyEndpointWithFailover(ep); err != nil {
			syncErrors = append(syncErrors, fmt.Sprintf("%s: %v", ep.Name, err))
			r.logger.Error("Failed to apply VTEP endpoint",
				logfields.Name, ep.Name,
				logfields.Error, err)
		} else {
			r.logger.Info("Successfully applied VTEP endpoint",
				logfields.Name, ep.Name,
				"tunnelEndpoint", ep.TunnelEndpoint,
				"cidr", ep.CIDR)
		}
	}

	// Update manager config with all endpoints for route management.
	// Routes are CIDR-keyed, so they don't change on failover.
	if r.manager != nil {
		mgConfig := vtepManagerConfig{}
		for _, ep := range config.Spec.Endpoints {
			tunnelEP := net.ParseIP(ep.TunnelEndpoint)
			if tunnelEP == nil {
				continue
			}
			externalCIDR, err := cidr.ParseCIDR(ep.CIDR)
			if err != nil {
				continue
			}
			externalMAC, err := mac.ParseMAC(ep.MAC)
			if err != nil {
				continue
			}
			mgConfig.vtepEndpoints = append(mgConfig.vtepEndpoints, tunnelEP)
			mgConfig.vtepCIDRs = append(mgConfig.vtepCIDRs, externalCIDR)
			mgConfig.vtepMACs = append(mgConfig.vtepMACs, externalMAC)
		}
		r.manager.config = mgConfig

		// Setup routes for all endpoints
		if err := r.manager.setupRouteToVTEPCidr(); err != nil {
			r.logger.Error("Failed to setup VTEP routes", logfields.Error, err)
			syncErrors = append(syncErrors, fmt.Sprintf("routes: %v", err))
		}
	}

	// Save config for failover event processing
	r.lastConfig = config.DeepCopy()

	// Update health monitor with current endpoints
	if r.healthMonitor != nil {
		r.healthMonitor.updateEndpoints(config.Spec.Endpoints)
	}

	// Update full status including health information
	r.updateFullStatus(ctx, config, syncErrors)

	if len(syncErrors) > 0 {
		return fmt.Errorf("sync errors: %v", syncErrors)
	}
	return nil
}

// applyEndpointWithFailover applies a VTEP endpoint to the BPF map,
// handling config-change-aware failover for endpoints with standby.
func (r *VTEPReconciler) applyEndpointWithFailover(ep cilium_api_v2.VTEPEndpoint) error {
	if ep.Standby == nil || r.healthMonitor == nil {
		// No standby — apply primary directly (backward-compatible path)
		return r.applyConnection(ep.CIDR, ep.TunnelEndpoint, ep.MAC)
	}

	// Endpoint has standby. Get current active role from health monitor.
	currentRole := r.healthMonitor.getCurrentRole(ep.Name)

	// Check if the config of the currently serving connection changed.
	// If so, promote the other connection first to avoid traffic loss.
	if r.lastConfig != nil {
		for _, prevEP := range r.lastConfig.Spec.Endpoints {
			if prevEP.Name != ep.Name || prevEP.Standby == nil {
				continue
			}

			switch currentRole {
			case "primary":
				// Primary is serving. Did the primary config change?
				if prevEP.TunnelEndpoint != ep.TunnelEndpoint || prevEP.MAC != ep.MAC {
					r.logger.Info("Active primary config changed, promoting standby first",
						logfields.Name, ep.Name)
					// Promote standby to BPF map
					if err := r.applyConnection(ep.CIDR, ep.Standby.TunnelEndpoint, ep.Standby.MAC); err != nil {
						return fmt.Errorf("failed to promote standby during config change: %w", err)
					}
					r.healthMonitor.setCurrentRole(ep.Name, "standby")
					return nil
				}
			case "standby":
				// Standby is serving. Did the standby config change?
				if prevEP.Standby.TunnelEndpoint != ep.Standby.TunnelEndpoint || prevEP.Standby.MAC != ep.Standby.MAC {
					r.logger.Info("Active standby config changed, promoting primary first",
						logfields.Name, ep.Name)
					// Promote primary to BPF map
					if err := r.applyConnection(ep.CIDR, ep.TunnelEndpoint, ep.MAC); err != nil {
						return fmt.Errorf("failed to promote primary during config change: %w", err)
					}
					r.healthMonitor.setCurrentRole(ep.Name, "primary")
					return nil
				}
			}
			break
		}
	}

	// No serving-connection config change — apply the currently active connection
	tunnelEP, macAddr := r.healthMonitor.getActiveConnection(ep)
	return r.applyConnection(ep.CIDR, tunnelEP, macAddr)
}

// applyConnection writes a single tunnel endpoint + MAC to the BPF map for a given CIDR.
func (r *VTEPReconciler) applyConnection(cidrStr string, tunnelEndpoint string, macAddr string) error {
	tunnelEP := net.ParseIP(tunnelEndpoint)
	if tunnelEP == nil {
		return fmt.Errorf("invalid tunnel endpoint IP: %s", tunnelEndpoint)
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

// reconcileDelete handles deletion of a CiliumVTEPConfig.
func (r *VTEPReconciler) reconcileDelete(ctx context.Context, config *cilium_api_v2.CiliumVTEPConfig) error {
	r.logger.Info("Reconciling VTEP config delete", logfields.Name, config.Name)

	// Delete all endpoints from BPF map using CIDR as the key
	for _, ep := range config.Spec.Endpoints {
		externalCIDR, err := cidr.ParseCIDR(ep.CIDR)
		if err != nil {
			r.logger.Warn("Invalid CIDR, skipping delete",
				logfields.Name, ep.Name,
				"cidr", ep.CIDR,
				logfields.Error, err)
			continue
		}

		if err := r.vtepMap.DeleteByCIDR(externalCIDR.IP); err != nil {
			r.logger.Error("Failed to delete VTEP endpoint from BPF map",
				logfields.Name, ep.Name,
				"cidr", ep.CIDR,
				logfields.Error, err)
		} else {
			r.logger.Info("Deleted VTEP endpoint from BPF map",
				logfields.Name, ep.Name,
				"cidr", ep.CIDR)
		}
	}

	// Clear manager config and clean up routes
	if r.manager != nil {
		r.manager.config = vtepManagerConfig{}
		if err := r.manager.setupRouteToVTEPCidr(); err != nil {
			r.logger.Error("Failed to clean up VTEP routes", logfields.Error, err)
		}
	}

	// Clear health monitor state
	if r.healthMonitor != nil {
		r.healthMonitor.updateEndpoints(nil)
	}

	r.lastConfig = nil

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
	cidrs := make(map[string]bool)
	for _, ep := range config.Spec.Endpoints {
		// Check for duplicate names
		if names[ep.Name] {
			return fmt.Errorf("duplicate endpoint name: %s", ep.Name)
		}
		names[ep.Name] = true

		// Check for duplicate CIDRs (BPF map is keyed by CIDR IP)
		if cidrs[ep.CIDR] {
			return fmt.Errorf("duplicate CIDR %s (endpoint %s): each CIDR can only appear once", ep.CIDR, ep.Name)
		}
		cidrs[ep.CIDR] = true

		// Validate tunnel endpoint
		if net.ParseIP(ep.TunnelEndpoint) == nil {
			return fmt.Errorf("invalid tunnel endpoint IP for %s: %s", ep.Name, ep.TunnelEndpoint)
		}

		// Validate CIDR
		if _, _, err := net.ParseCIDR(ep.CIDR); err != nil {
			return fmt.Errorf("invalid CIDR for %s: %s", ep.Name, ep.CIDR)
		}

		// Validate MAC
		if _, err := mac.ParseMAC(ep.MAC); err != nil {
			return fmt.Errorf("invalid MAC for %s: %s", ep.Name, ep.MAC)
		}

		// Validate standby if configured
		if ep.Standby != nil {
			if net.ParseIP(ep.Standby.TunnelEndpoint) == nil {
				return fmt.Errorf("invalid standby tunnel endpoint IP for %s: %s", ep.Name, ep.Standby.TunnelEndpoint)
			}
			if _, err := mac.ParseMAC(ep.Standby.MAC); err != nil {
				return fmt.Errorf("invalid standby MAC for %s: %s", ep.Name, ep.Standby.MAC)
			}
			if ep.TunnelEndpoint == ep.Standby.TunnelEndpoint {
				return fmt.Errorf("standby tunnel endpoint must differ from primary for %s", ep.Name)
			}
		}
	}

	return nil
}

// updateStatus updates the status with a simple ready/not-ready condition.
func (r *VTEPReconciler) updateStatus(ctx context.Context, config *cilium_api_v2.CiliumVTEPConfig, ready bool, errMsg string) {
	r.updateStatusWithEndpoints(ctx, config, ready, errMsg, nil)
}

// updateFullStatus updates the CRD status with sync info and health information
// from the health monitor (single-writer pattern). syncErrors contains per-endpoint
// error strings from the most recent reconcile; nil means all synced.
func (r *VTEPReconciler) updateFullStatus(ctx context.Context, config *cilium_api_v2.CiliumVTEPConfig, syncErrors []string) {
	if r.clientset == nil || !r.clientset.IsEnabled() {
		return
	}

	endpointStatuses := make([]cilium_api_v2.VTEPEndpointStatus, 0, len(config.Spec.Endpoints))
	allSynced := len(syncErrors) == 0
	hasStandby := false

	for _, ep := range config.Spec.Endpoints {
		epSynced := true
		var epError string
		// Check if this endpoint had a sync error
		for _, e := range syncErrors {
			prefix := ep.Name + ": "
			if len(e) > len(prefix) && e[:len(prefix)] == prefix {
				epSynced = false
				epError = e[len(prefix):]
				break
			}
		}

		status := cilium_api_v2.VTEPEndpointStatus{
			Name:   ep.Name,
			Synced: epSynced,
			Error:  epError,
		}
		if epSynced {
			now := metav1.Now()
			status.LastSyncTime = &now
		}

		// Add health info if available
		if r.healthMonitor != nil && ep.Standby != nil {
			hasStandby = true
			activeRole, primaryHealth, standbyHealth, lastFailoverTime, failoverCount :=
				r.healthMonitor.buildEndpointHealthStatus(ep.Name)

			if activeRole != "" {
				status.ActiveRole = activeRole
			}
			status.PrimaryHealth = primaryHealth
			status.StandbyHealth = standbyHealth
			if lastFailoverTime != nil {
				t := metav1.NewTime(*lastFailoverTime)
				status.LastFailoverTime = &t
			}
			status.FailoverCount = failoverCount
		}

		endpointStatuses = append(endpointStatuses, status)
	}

	configCopy := config.DeepCopy()
	configCopy.Status.EndpointCount = len(config.Spec.Endpoints)
	configCopy.Status.EndpointStatuses = endpointStatuses
	configCopy.Status.ActiveSummary = buildActiveSummary(endpointStatuses)

	// Set Ready condition
	now := metav1.Now()
	readyCondition := metav1.Condition{
		Type:               cilium_api_v2.VTEPConditionReady,
		LastTransitionTime: now,
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
	setCondition(&configCopy.Status.Conditions, readyCondition)

	// Set HealthMonitoring condition if any endpoint has standby
	if hasStandby {
		healthCondition := metav1.Condition{
			Type:               cilium_api_v2.VTEPConditionHealthMonitoring,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: now,
			ObservedGeneration: config.Generation,
			Reason:             "Active",
			Message:            "ICMP health monitoring active for endpoints with standby",
		}
		setCondition(&configCopy.Status.Conditions, healthCondition)

		// Set FailoverReady condition — checks whether the backup (non-active)
		// connection is healthy for each endpoint, so failover is possible if needed.
		backupHealthy := true
		for _, epStatus := range endpointStatuses {
			switch epStatus.ActiveRole {
			case "primary":
				// Backup is standby — check standby health
				if epStatus.StandbyHealth != nil && !epStatus.StandbyHealth.Healthy {
					backupHealthy = false
				}
			case "standby":
				// Backup is primary — check primary health
				if epStatus.PrimaryHealth != nil && !epStatus.PrimaryHealth.Healthy {
					backupHealthy = false
				}
			}
			if !backupHealthy {
				break
			}
		}

		failoverCondition := metav1.Condition{
			Type:               cilium_api_v2.VTEPConditionFailoverReady,
			LastTransitionTime: now,
			ObservedGeneration: config.Generation,
		}
		if backupHealthy {
			failoverCondition.Status = metav1.ConditionTrue
			failoverCondition.Reason = "Healthy"
			failoverCondition.Message = "All standby connections are healthy"
		} else {
			failoverCondition.Status = metav1.ConditionFalse
			failoverCondition.Reason = "Degraded"
			failoverCondition.Message = "Some connections are unhealthy"
		}
		setCondition(&configCopy.Status.Conditions, failoverCondition)
	}

	// Update status in API server with retry on conflict
	r.updateStatusWithRetry(ctx, configCopy)
}

// updateStatusWithEndpoints updates the status of a CiliumVTEPConfig with endpoint statuses.
func (r *VTEPReconciler) updateStatusWithEndpoints(ctx context.Context, config *cilium_api_v2.CiliumVTEPConfig, ready bool, errMsg string, endpointStatuses []cilium_api_v2.VTEPEndpointStatus) {
	if r.clientset == nil || !r.clientset.IsEnabled() {
		return
	}

	configCopy := config.DeepCopy()
	configCopy.Status.EndpointCount = len(config.Spec.Endpoints)

	if endpointStatuses != nil {
		configCopy.Status.EndpointStatuses = endpointStatuses
	}

	now := metav1.Now()
	readyCondition := metav1.Condition{
		Type:               cilium_api_v2.VTEPConditionReady,
		LastTransitionTime: now,
		ObservedGeneration: config.Generation,
	}

	if ready {
		readyCondition.Status = metav1.ConditionTrue
		readyCondition.Reason = "Synced"
		readyCondition.Message = "All endpoints synced to BPF map"
	} else {
		readyCondition.Status = metav1.ConditionFalse
		readyCondition.Reason = "SyncFailed"
		readyCondition.Message = errMsg
	}
	setCondition(&configCopy.Status.Conditions, readyCondition)

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
		// Conflict — re-fetch and reapply status
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
		// Copy our status into the fresh object
		fresh.Status = configCopy.Status
		configCopy = fresh
	}
}

// setCondition updates or adds a condition in the conditions slice.
func setCondition(conditions *[]metav1.Condition, newCondition metav1.Condition) {
	for i, cond := range *conditions {
		if cond.Type == newCondition.Type {
			(*conditions)[i] = newCondition
			return
		}
	}
	*conditions = append(*conditions, newCondition)
}

// GetCRDConfig retrieves the default CiliumVTEPConfig if it exists.
func (r *VTEPReconciler) GetCRDConfig(ctx context.Context) (*cilium_api_v2.CiliumVTEPConfig, error) {
	if r.resource == nil {
		return nil, fmt.Errorf("VTEP config resource not available")
	}

	store, err := r.resource.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get VTEP config store: %w", err)
	}

	for _, item := range store.List() {
		if item.Name == "default" {
			return item, nil
		}
	}

	items := store.List()
	if len(items) > 0 {
		return items[0], nil
	}

	return nil, fmt.Errorf("no CiliumVTEPConfig found")
}

// SyncFromCRD synchronizes VTEP configuration from the CRD to the BPF map.
func (r *VTEPReconciler) SyncFromCRD(ctx context.Context) error {
	config, err := r.GetCRDConfig(ctx)
	if err != nil {
		return err
	}

	return r.reconcileUpsert(ctx, config)
}

// buildActiveSummary generates a compact summary of failover state.
// Examples: "all-primary", "1/3 on standby"
func buildActiveSummary(statuses []cilium_api_v2.VTEPEndpointStatus) string {
	monitored := 0
	onStandby := 0

	for _, s := range statuses {
		if s.ActiveRole != "" {
			monitored++
			if s.ActiveRole == "standby" {
				onStandby++
			}
		}
	}

	if monitored == 0 || onStandby == 0 {
		return "all-primary"
	}

	return fmt.Sprintf("%d/%d on standby", onStandby, monitored)
}

