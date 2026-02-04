// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/cidr"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/vtep"
)

// VTEPReconciler watches CiliumVTEPConfig CRD and reconciles changes to the BPF map.
type VTEPReconciler struct {
	logger    *slog.Logger
	vtepMap   vtep.Map
	clientset client.Clientset
	resource  resource.Resource[*cilium_api_v2.CiliumVTEPConfig]
	manager   *vtepManager
}

// vtepReconcilerParams contains parameters for creating a VTEPReconciler.
type vtepReconcilerParams struct {
	Logger    *slog.Logger
	VTEPMap   vtep.Map
	Clientset client.Clientset
	Resource  resource.Resource[*cilium_api_v2.CiliumVTEPConfig]
	Manager   *vtepManager
}

// newVTEPReconciler creates a new VTEPReconciler instance.
func newVTEPReconciler(params vtepReconcilerParams) *VTEPReconciler {
	return &VTEPReconciler{
		logger:    params.Logger,
		vtepMap:   params.VTEPMap,
		clientset: params.Clientset,
		resource:  params.Resource,
		manager:   params.Manager,
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
		switch event.Kind {
		case resource.Sync:
			r.logger.Debug("VTEP CRD resource synced")
		case resource.Upsert:
			if err := r.reconcileUpsert(ctx, event.Object); err != nil {
				r.logger.Error("Failed to reconcile VTEP config upsert",
					logfields.Error, err,
					logfields.Name, event.Object.Name)
			}
		case resource.Delete:
			if err := r.reconcileDelete(ctx, event.Object); err != nil {
				r.logger.Error("Failed to reconcile VTEP config delete",
					logfields.Error, err,
					logfields.Name, event.Object.Name)
			}
		}
		event.Done(nil)
	}

	return nil
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

	// Parse and apply each endpoint
	var syncErrors []string
	endpointStatuses := make([]cilium_api_v2.VTEPEndpointStatus, 0, len(config.Spec.Endpoints))

	for _, ep := range config.Spec.Endpoints {
		status := cilium_api_v2.VTEPEndpointStatus{
			Name:   ep.Name,
			Synced: false,
		}

		if err := r.applyEndpoint(ep); err != nil {
			status.Error = err.Error()
			syncErrors = append(syncErrors, fmt.Sprintf("%s: %v", ep.Name, err))
			r.logger.Error("Failed to apply VTEP endpoint",
				logfields.Name, ep.Name,
				logfields.Error, err)
		} else {
			status.Synced = true
			now := metav1.Now()
			status.LastSyncTime = &now
			r.logger.Info("Successfully applied VTEP endpoint",
				logfields.Name, ep.Name,
				"tunnelEndpoint", ep.TunnelEndpoint,
				"cidr", ep.CIDR)
		}

		endpointStatuses = append(endpointStatuses, status)
	}

	// Update manager config with all endpoints for route management
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

	// Update status
	allSynced := len(syncErrors) == 0
	var errMsg string
	if !allSynced {
		errMsg = fmt.Sprintf("sync errors: %v", syncErrors)
	}
	r.updateStatusWithEndpoints(ctx, config, allSynced, errMsg, endpointStatuses)

	return nil
}

// reconcileDelete handles deletion of a CiliumVTEPConfig.
func (r *VTEPReconciler) reconcileDelete(ctx context.Context, config *cilium_api_v2.CiliumVTEPConfig) error {
	r.logger.Info("Reconciling VTEP config delete", logfields.Name, config.Name)

	// Delete all endpoints from BPF map using CIDR as the key
	for _, ep := range config.Spec.Endpoints {
		// Parse CIDR to get the IP for the BPF map key
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
		// setupRouteToVTEPCidr will remove routes since config.vtepCIDRs is now empty
		if err := r.manager.setupRouteToVTEPCidr(); err != nil {
			r.logger.Error("Failed to clean up VTEP routes", logfields.Error, err)
		}
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
	for _, ep := range config.Spec.Endpoints {
		// Check for duplicate names
		if names[ep.Name] {
			return fmt.Errorf("duplicate endpoint name: %s", ep.Name)
		}
		names[ep.Name] = true

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
	}

	return nil
}

// applyEndpoint applies a single VTEP endpoint to the BPF map.
func (r *VTEPReconciler) applyEndpoint(ep cilium_api_v2.VTEPEndpoint) error {
	// Parse tunnel endpoint IP
	tunnelEP := net.ParseIP(ep.TunnelEndpoint)
	if tunnelEP == nil {
		return fmt.Errorf("invalid tunnel endpoint IP: %s", ep.TunnelEndpoint)
	}

	// Parse CIDR
	externalCIDR, err := cidr.ParseCIDR(ep.CIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	// Parse MAC
	externalMAC, err := mac.ParseMAC(ep.MAC)
	if err != nil {
		return fmt.Errorf("invalid MAC: %w", err)
	}

	// Update BPF map
	if err := r.vtepMap.Update(externalCIDR, tunnelEP, externalMAC); err != nil {
		return fmt.Errorf("failed to update BPF map: %w", err)
	}

	return nil
}

// updateStatus updates the status of a CiliumVTEPConfig.
func (r *VTEPReconciler) updateStatus(ctx context.Context, config *cilium_api_v2.CiliumVTEPConfig, ready bool, errMsg string) {
	r.updateStatusWithEndpoints(ctx, config, ready, errMsg, nil)
}

// updateStatusWithEndpoints updates the status of a CiliumVTEPConfig with endpoint statuses.
func (r *VTEPReconciler) updateStatusWithEndpoints(ctx context.Context, config *cilium_api_v2.CiliumVTEPConfig, ready bool, errMsg string, endpointStatuses []cilium_api_v2.VTEPEndpointStatus) {
	if r.clientset == nil || !r.clientset.IsEnabled() {
		return
	}

	// Create a copy for status update
	configCopy := config.DeepCopy()

	// Update endpoint count
	configCopy.Status.EndpointCount = len(config.Spec.Endpoints)

	// Update endpoint statuses
	if endpointStatuses != nil {
		configCopy.Status.EndpointStatuses = endpointStatuses
	}

	// Update conditions
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

	// Update or add the Ready condition
	found := false
	for i, cond := range configCopy.Status.Conditions {
		if cond.Type == cilium_api_v2.VTEPConditionReady {
			configCopy.Status.Conditions[i] = readyCondition
			found = true
			break
		}
	}
	if !found {
		configCopy.Status.Conditions = append(configCopy.Status.Conditions, readyCondition)
	}

	// Update status in API server
	_, err := r.clientset.CiliumV2().CiliumVTEPConfigs().UpdateStatus(ctx, configCopy, metav1.UpdateOptions{})
	if err != nil {
		r.logger.Error("Failed to update CiliumVTEPConfig status",
			logfields.Name, config.Name,
			logfields.Error, err)
	}
}

// HasCRDConfig checks if a CiliumVTEPConfig CRD exists with valid endpoints.
func (r *VTEPReconciler) HasCRDConfig(ctx context.Context) bool {
	if r.resource == nil {
		return false
	}

	store, err := r.resource.Store(ctx)
	if err != nil {
		r.logger.Debug("Failed to get VTEP config store", logfields.Error, err)
		return false
	}

	// Check for any CiliumVTEPConfig with endpoints
	for _, item := range store.List() {
		if len(item.Spec.Endpoints) > 0 {
			return true
		}
	}

	return false
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

	// Look for a config named "default" or return the first one
	for _, item := range store.List() {
		if item.Name == "default" {
			return item, nil
		}
	}

	// Return first available config
	items := store.List()
	if len(items) > 0 {
		return items[0], nil
	}

	return nil, fmt.Errorf("no CiliumVTEPConfig found")
}

// SyncFromCRD synchronizes VTEP configuration from the CRD to the BPF map.
// This is called during initial startup to sync existing CRD config.
func (r *VTEPReconciler) SyncFromCRD(ctx context.Context) error {
	config, err := r.GetCRDConfig(ctx)
	if err != nil {
		return err
	}

	return r.reconcileUpsert(ctx, config)
}

// WaitForCRDSync waits for the CiliumVTEPConfig resource to be synced.
func (r *VTEPReconciler) WaitForCRDSync(ctx context.Context, timeout time.Duration) error {
	if r.resource == nil {
		return fmt.Errorf("VTEP config resource not available")
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	store, err := r.resource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to get VTEP config store: %w", err)
	}

	// Just accessing the store means it's been synced
	_ = store.List()
	return nil
}
