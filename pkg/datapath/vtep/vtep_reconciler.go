// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"reflect"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/cidr"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/vtep"
)

const (
	// vtepStatusFieldManager identifies the agent as the writer of the
	// CiliumVTEPNodeConfig /status subresource (server-side apply field manager).
	vtepStatusFieldManager = "cilium-vtep-agent"
)

// appliedEndpoint tracks the last-applied BPF state for a given CIDR.
type appliedEndpoint struct {
	tunnelEndpoint string
	mac            string
}

// desiredEP represents a resolved endpoint keyed by normalized CIDR string.
type desiredEP struct {
	endpoint cilium_api_v2alpha1.VTEPEndpoint
	cidrStr  string // original CIDR string from the node config spec
}

// jsonPatch is a single RFC6902 JSON patch operation.
type jsonPatch struct {
	OP    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// VTEPReconciler watches this node's CiliumVTEPNodeConfig (created and populated by
// the Cilium operator) and reconciles the resolved VTEP endpoints into the BPF map
// and Linux routes. It is the sole writer of its own node's .status subresource and
// never evaluates nodeSelectors (the operator does that) nor writes the cluster-scoped
// CiliumVTEPConfig.
type VTEPReconciler struct {
	logger    *slog.Logger
	vtepMap   vtep.Map
	clientset client.Clientset
	resource  resource.Resource[*cilium_api_v2alpha1.CiliumVTEPNodeConfig]
	manager   *vtepManager

	// mu protects nodeConfig, lastApplied, and BPF map operations.
	mu lock.Mutex

	// nodeConfig is this node's CiliumVTEPNodeConfig (nil if absent or deleted).
	nodeConfig *cilium_api_v2alpha1.CiliumVTEPNodeConfig
	// nodeName is the name of this node's CiliumVTEPNodeConfig (== node name).
	nodeName string

	// lastApplied tracks the last BPF state, keyed by normalized CIDR string
	// (e.g. "10.1.1.0/24"). This matches the LPM trie key: {prefixlen, network_ip}.
	lastApplied map[string]appliedEndpoint

	// initialCleanupDone tracks whether the first-run BPF map cleanup has been done.
	initialCleanupDone bool

	// crdSynced is set after the resource.Sync event is received.
	crdSynced bool

	// lastStatus is the status this agent last successfully wrote to its own
	// CiliumVTEPNodeConfig. It is the authoritative basis for condition
	// LastTransitionTime and lets updateNodeConfigStatus skip no-op /status writes.
	lastStatus *cilium_api_v2alpha1.CiliumVTEPNodeConfigStatus
}

// vtepReconcilerParams contains parameters for creating a VTEPReconciler.
type vtepReconcilerParams struct {
	Logger    *slog.Logger
	VTEPMap   vtep.Map
	Clientset client.Clientset
	Resource  resource.Resource[*cilium_api_v2alpha1.CiliumVTEPNodeConfig]
	Manager   *vtepManager
}

// newVTEPReconciler creates a new VTEPReconciler instance.
func newVTEPReconciler(params vtepReconcilerParams) *VTEPReconciler {
	return &VTEPReconciler{
		logger:      params.Logger,
		vtepMap:     params.VTEPMap,
		clientset:   params.Clientset,
		resource:    params.Resource,
		manager:     params.Manager,
		lastApplied: make(map[string]appliedEndpoint),
	}
}

// Run starts the reconciler loop that watches this node's CiliumVTEPNodeConfig.
func (r *VTEPReconciler) Run(ctx context.Context) error {
	if r.resource == nil {
		r.logger.Debug("CiliumVTEPNodeConfig resource not available, reconciler not starting")
		return nil
	}

	r.logger.Info("Starting VTEP node-config reconciler")

	for event := range r.resource.Events(ctx) {
		var (
			epErrors  map[string]error
			err       error
			writeStat bool
		)
		switch event.Kind {
		case resource.Sync:
			r.mu.Lock()
			r.crdSynced = true
			epErrors, err = r.reconcileLocked()
			r.mu.Unlock()
			writeStat = true
		case resource.Upsert:
			r.mu.Lock()
			r.nodeConfig = event.Object.DeepCopy()
			r.nodeName = event.Object.Name
			epErrors, err = r.reconcileLocked()
			r.mu.Unlock()
			writeStat = true
		case resource.Delete:
			r.mu.Lock()
			r.nodeConfig = nil
			r.nodeName = ""
			r.lastStatus = nil
			epErrors, err = r.reconcileLocked()
			r.mu.Unlock()
			// The object is gone; there is nothing to write status to.
			writeStat = false
		}
		if writeStat {
			r.updateNodeConfigStatus(ctx, epErrors)
		}
		event.Done(err)
	}

	return nil
}

// reconcileLocked diffs the resolved endpoints in this node's CiliumVTEPNodeConfig
// against the last-applied BPF state and reconciles the BPF map + Linux routes.
// It returns per-endpoint errors (keyed by endpoint name) and an aggregate error.
// Caller must hold r.mu.
//
// nodeSelector evaluation and cross-config CIDR-conflict resolution are performed by
// the operator before it writes Spec.VTEPEndpoints, so the agent simply programs the
// resolved set.
func (r *VTEPReconciler) reconcileLocked() (map[string]error, error) {
	// desired is keyed by the normalized CIDR string (e.g. "10.1.1.0/24").
	// cidr.ParseCIDR normalizes host bits so "10.1.1.5/24" → "10.1.1.0/24".
	// This string maps 1:1 to the LPM trie key {prefixlen=24, ip=10.1.1.0}.
	desired := make(map[string]desiredEP)
	epErrors := make(map[string]error)

	if r.nodeConfig != nil {
		for _, ep := range r.nodeConfig.Spec.VTEPEndpoints {
			externalCIDR, err := cidr.ParseCIDR(ep.CIDR)
			if err != nil {
				epErrors[ep.Name] = fmt.Errorf("invalid CIDR %s: %w", ep.CIDR, err)
				continue
			}
			if externalCIDR.IP.To4() == nil {
				epErrors[ep.Name] = fmt.Errorf("CIDR must be IPv4: %s", ep.CIDR)
				continue
			}
			// Normalized CIDR string is the BPF LPM key: {prefixlen, network_ip}.
			cidrKey := externalCIDR.String()
			if _, dup := desired[cidrKey]; dup {
				epErrors[ep.Name] = fmt.Errorf("duplicate CIDR %s", cidrKey)
				continue
			}
			desired[cidrKey] = desiredEP{endpoint: ep, cidrStr: ep.CIDR}
		}
	}

	if len(desired) > vtep.MaxEntries {
		err := fmt.Errorf("resolved endpoints (%d) exceed maximum (%d)", len(desired), vtep.MaxEntries)
		r.logger.Error(err.Error())
		return epErrors, err
	}

	// Apply/update desired endpoints (add before delete to avoid traffic drops).
	for cidrKey, dep := range desired {
		ep := dep.endpoint

		if existing, ok := r.lastApplied[cidrKey]; ok &&
			existing.tunnelEndpoint == ep.TunnelEndpoint &&
			existing.mac == ep.MAC {
			continue
		}

		if err := r.applyConnection(dep.cidrStr, ep.TunnelEndpoint, ep.MAC); err != nil {
			epErrors[ep.Name] = err
			r.logger.Error("Failed to apply VTEP endpoint",
				logfields.Name, ep.Name,
				logfields.Error, err)
		} else {
			r.lastApplied[cidrKey] = appliedEndpoint{
				tunnelEndpoint: ep.TunnelEndpoint,
				mac:            ep.MAC,
			}
			r.logger.Info("Successfully applied VTEP endpoint",
				logfields.Name, ep.Name,
				logfields.TunnelPeer, ep.TunnelEndpoint,
				logfields.CIDR, dep.cidrStr)
		}
	}

	// On first reconcile after CRD sync, clean up stale BPF map entries
	// left from a previous agent run.
	if !r.initialCleanupDone && r.crdSynced {
		r.cleanupStaleBPFEntries(desired)
		r.initialCleanupDone = true
	}

	// Delete stale entries from lastApplied that are no longer desired.
	for cidrKey := range r.lastApplied {
		if _, stillDesired := desired[cidrKey]; stillDesired {
			continue
		}
		parsedCIDR, err := cidr.ParseCIDR(cidrKey)
		if err != nil {
			r.logger.Warn("Invalid CIDR key in lastApplied, skipping delete",
				logfields.CIDR, cidrKey)
			continue
		}
		if err := r.vtepMap.Delete(parsedCIDR); err != nil {
			r.logger.Warn("Failed to delete stale VTEP BPF entry, will retry on next sync",
				logfields.CIDR, cidrKey,
				logfields.Error, err)
			continue
		}
		r.logger.Info("Deleted stale VTEP BPF entry", logfields.CIDR, cidrKey)
		delete(r.lastApplied, cidrKey)
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

	var syncErr error
	if len(epErrors) > 0 {
		syncErr = fmt.Errorf("%d VTEP endpoint(s) failed to sync", len(epErrors))
	}
	return epErrors, syncErr
}

// cleanupStaleBPFEntries removes BPF map entries not present in desired.
// Called on first reconcile to handle agent restarts.
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
				logfields.CIDR, entry.CIDR)
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
					logfields.CIDR, entryKey,
					logfields.Error, err)
				continue
			}
			if err := r.vtepMap.Delete(parsedCIDR); err != nil {
				r.logger.Warn("Failed to delete stale BPF map entry on startup",
					logfields.CIDR, entryKey,
					logfields.Error, err)
			} else {
				r.logger.Info("Cleaned up stale BPF map entry on startup",
					logfields.CIDR, entryKey)
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

// updateNodeConfigStatus writes per-endpoint sync state and a Ready condition to this
// node's own CiliumVTEPNodeConfig /status subresource. It uses a JSON-patch replace of
// /status (single-writer-per-node, no ResourceVersion contention) and tolerates the
// object having been deleted.
func (r *VTEPReconciler) updateNodeConfigStatus(ctx context.Context, epErrors map[string]error) {
	if r.clientset == nil || !r.clientset.IsEnabled() {
		return
	}

	r.mu.Lock()
	cfg := r.nodeConfig
	nodeName := r.nodeName
	prior := r.lastStatus
	r.mu.Unlock()

	if cfg == nil || nodeName == "" {
		return
	}

	status := buildNodeConfigStatus(cfg, epErrors, prior, metav1.Now())

	// Skip the write when nothing changed since our last successful write. Avoids
	// re-patching /status on every reconcile (e.g. watch relists) — the agent is the
	// sole writer, so our cached lastStatus is authoritative.
	if prior != nil && reflect.DeepEqual(*prior, status) {
		return
	}

	patchBytes, err := json.Marshal([]jsonPatch{{OP: "replace", Path: "/status", Value: status}})
	if err != nil {
		r.logger.Error("Failed to marshal CiliumVTEPNodeConfig status patch",
			logfields.Name, nodeName,
			logfields.Error, err)
		return
	}

	_, err = r.clientset.CiliumV2alpha1().CiliumVTEPNodeConfigs().Patch(
		ctx, nodeName, k8stypes.JSONPatchType, patchBytes,
		metav1.PatchOptions{FieldManager: vtepStatusFieldManager}, "status")
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return
		}
		r.logger.Error("Failed to update CiliumVTEPNodeConfig status",
			logfields.Name, nodeName,
			logfields.Error, err)
		return
	}

	// Remember what we wrote so subsequent reconciles can dedup and compute condition
	// transitions against it.
	r.mu.Lock()
	r.lastStatus = &status
	if r.nodeConfig != nil && r.nodeConfig.Name == nodeName {
		r.nodeConfig.Status = status
	}
	r.mu.Unlock()
}

// buildNodeConfigStatus computes the status to write for this node's CiliumVTEPNodeConfig
// from the reconcile result. prior is the agent's last-written status (or nil); it keeps
// LastSyncTime stable for endpoints that remain synced (only stamping `now` on a
// transition to synced) and bases condition LastTransitionTime on the agent's own
// history rather than the possibly-lagging informer object. Pure and deterministic given
// (cfg, epErrors, prior, now) so the result can be compared for no-op dedup.
func buildNodeConfigStatus(
	cfg *cilium_api_v2alpha1.CiliumVTEPNodeConfig,
	epErrors map[string]error,
	prior *cilium_api_v2alpha1.CiliumVTEPNodeConfigStatus,
	now metav1.Time,
) cilium_api_v2alpha1.CiliumVTEPNodeConfigStatus {
	priorEP := make(map[string]cilium_api_v2alpha1.VTEPEndpointStatus)
	if prior != nil {
		for _, st := range prior.VTEPEndpointStatuses {
			priorEP[st.Name] = st
		}
	}

	endpointStatuses := make([]cilium_api_v2alpha1.VTEPEndpointStatus, 0, len(cfg.Spec.VTEPEndpoints))
	allSynced := true
	for _, ep := range cfg.Spec.VTEPEndpoints {
		st := cilium_api_v2alpha1.VTEPEndpointStatus{Name: ep.Name, Synced: true}
		if err, bad := epErrors[ep.Name]; bad {
			st.Synced = false
			st.Error = err.Error()
			allSynced = false
		} else if p, ok := priorEP[ep.Name]; ok && p.Synced && p.LastSyncTime != nil {
			st.LastSyncTime = p.LastSyncTime
		} else {
			t := now
			st.LastSyncTime = &t
		}
		endpointStatuses = append(endpointStatuses, st)
	}

	status := cilium_api_v2alpha1.CiliumVTEPNodeConfigStatus{
		EndpointCount:        int32(len(cfg.Spec.VTEPEndpoints)),
		VTEPEndpointStatuses: endpointStatuses,
	}

	readyCondition := metav1.Condition{
		Type:               cilium_api_v2alpha1.VTEPConditionReady,
		ObservedGeneration: cfg.Generation,
	}
	if allSynced {
		readyCondition.Status = metav1.ConditionTrue
		readyCondition.Reason = "AllEndpointsSynced"
		readyCondition.Message = fmt.Sprintf("All %d VTEP endpoints synced to BPF map", len(endpointStatuses))
	} else {
		readyCondition.Status = metav1.ConditionFalse
		readyCondition.Reason = "SyncFailed"
		readyCondition.Message = "Some VTEP endpoints failed to sync"
	}

	var conditions []metav1.Condition
	if prior != nil {
		conditions = append(conditions, prior.Conditions...)
	}
	setCondition(&conditions, readyCondition, now)
	status.Conditions = conditions

	return status
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
