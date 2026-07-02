// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/defaults"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// nodeResolution accumulates, for a single node, the VTEP endpoints contributed by
// every matching CiliumVTEPConfig plus the set of CIDRs that are in conflict.
type nodeResolution struct {
	// endpoints maps normalized CIDR string -> resolved endpoint (first writer wins
	// until a conflict removes it).
	endpoints map[string]v2alpha1.VTEPEndpoint
	// conflicts is the set of normalized CIDR strings claimed by more than one config.
	conflicts sets.Set[string]
	// owners are the matching CiliumVTEPConfig objects (for ownerReferences).
	owners []*v2alpha1.CiliumVTEPConfig
}

// reconcile resolves all CiliumVTEPConfig objects into per-node CiliumVTEPNodeConfig
// objects and garbage-collects per-node objects for nodes that no longer match.
func (m *VTEPResourceManager) reconcile(ctx context.Context) error {
	allConfigs := m.clusterConfigStore.List()
	nodes := m.ciliumNodeStore.List()

	// Pre-validate every config's nodeSelector. A selector that fails to parse is a
	// recoverable input error (nodeSelector has no admission-time CEL validation, so a
	// malformed selector is admitted and only fails here). We must NOT let it cascade
	// into deleting node configs for nodes it may have matched: dropping such a config
	// from resolution would remove those nodes from the desired set and the GC sweep
	// would tear down their VTEP tunnels. So we exclude only the offending config and,
	// while any selector is unparseable, skip the GC sweep entirely and return an error
	// so the pass is retried. This fails CLOSED, matching the CiliumBGPClusterConfig
	// reconciler (operator/pkg/bgp/cluster.go:116-119,59-62).
	//
	// Caveat: a node that matches BOTH a valid config and an unparseable-selector config
	// is reconciled to the valid config's endpoints only (the unparseable config cannot
	// be evaluated), so that config's endpoints are transiently absent until the selector
	// is fixed. This is unavoidable and strictly safer than deleting the node config; it
	// self-heals on the next pass once the selector parses.
	var selectorErr error
	configs := make([]*v2alpha1.CiliumVTEPConfig, 0, len(allConfigs))
	for _, cfg := range allConfigs {
		if _, err := selectorForConfig(cfg); err != nil {
			m.logger.Error("Invalid nodeSelector in CiliumVTEPConfig; skipping node-config GC this pass to avoid tearing down VTEP state",
				logfields.Name, cfg.Name,
				logfields.Error, err)
			selectorErr = errors.Join(selectorErr, fmt.Errorf("config %q: invalid nodeSelector: %w", cfg.Name, err))
			continue
		}
		configs = append(configs, cfg)
	}

	resolutions := make(map[string]*nodeResolution)
	for _, node := range nodes {
		if res := resolveNode(node.Name, node.Labels, configs, m.logger); res != nil {
			resolutions[node.Name] = res
		}
	}

	desiredNodes := sets.New[string]()
	var errs error
	for nodeName, res := range resolutions {
		desiredNodes.Insert(nodeName)
		if err := m.upsertNodeConfig(ctx, nodeName, res); err != nil {
			m.logger.Warn("Failed to upsert CiliumVTEPNodeConfig",
				logfields.Node, nodeName,
				logfields.Error, err)
			errs = errors.Join(errs, err)
		}
	}

	// Garbage-collect node configs for nodes that no longer match any config.
	// The operator is the sole creator of CiliumVTEPNodeConfig, so any object whose
	// node is not in desiredNodes is stale. Skipped while any selector is unparseable
	// (see above) so a transient bad selector cannot delete valid node configs.
	if selectorErr == nil {
		for _, nc := range m.nodeConfigStore.List() {
			if desiredNodes.Has(nc.Name) {
				continue
			}
			if err := m.nodeConfigClient.Delete(ctx, nc.Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
				m.logger.Warn("Failed to delete stale CiliumVTEPNodeConfig",
					logfields.Node, nc.Name,
					logfields.Error, err)
				errs = errors.Join(errs, err)
			} else {
				m.logger.Info("Deleted stale CiliumVTEPNodeConfig", logfields.Node, nc.Name)
			}
		}
	}

	// Surface unparseable selectors as a (retryable) reconcile error so they are not
	// silently swallowed and the pass is retried with backoff.
	return errors.Join(errs, selectorErr)
}

// upsertNodeConfig creates or updates the CiliumVTEPNodeConfig for a node from its
// resolved endpoint set.
func (m *VTEPResourceManager) upsertNodeConfig(ctx context.Context, nodeName string, res *nodeResolution) error {
	endpoints := sortedEndpoints(res.endpoints)
	if len(endpoints) > defaults.MaxVTEPDevices {
		m.logger.Error("Resolved VTEP endpoints exceed per-node maximum, truncating",
			logfields.Node, nodeName,
			logfields.Count, len(endpoints),
			logfields.Max, defaults.MaxVTEPDevices)
		endpoints = endpoints[:defaults.MaxVTEPDevices]
	}

	ownerRefs := ownerReferences(res.owners)

	existing, exists, err := m.nodeConfigStore.GetByKey(resource.Key{Name: nodeName})
	if err != nil {
		return err
	}

	if !exists {
		newObj := &v2alpha1.CiliumVTEPNodeConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:            nodeName,
				OwnerReferences: ownerRefs,
			},
			Spec: v2alpha1.CiliumVTEPNodeConfigSpec{
				VTEPEndpoints: endpoints,
			},
		}
		if _, err := m.nodeConfigClient.Create(ctx, newObj, metav1.CreateOptions{}); err != nil {
			// Includes IsAlreadyExists: the store hasn't observed an existing object yet.
			// Returning the (retryable) error lets reconcileWithRetry re-run; the next
			// pass sees the object in the store and takes the Update path. Don't log
			// "Created" on a no-op or swallow a divergent pre-existing spec.
			return err
		}
		m.logger.Info("Created CiliumVTEPNodeConfig",
			logfields.Node, nodeName,
			logfields.Count, len(endpoints),
		)
		return nil
	}

	desiredSpec := v2alpha1.CiliumVTEPNodeConfigSpec{VTEPEndpoints: endpoints}
	if existing.Spec.DeepEqual(&desiredSpec) && ownerRefsEqual(existing.OwnerReferences, ownerRefs) {
		return nil
	}

	// Update spec + owner references only. The .status subresource is owned by the
	// agent and is not modified by a spec Update.
	updated := existing.DeepCopy()
	updated.Spec = desiredSpec
	updated.OwnerReferences = ownerRefs
	if _, err := m.nodeConfigClient.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return err
	}
	m.logger.Info("Updated CiliumVTEPNodeConfig",
		logfields.Node, nodeName,
		logfields.Count, len(endpoints),
	)
	return nil
}

// resolveNode computes the conflict-free set of VTEP endpoints that apply to a node
// by evaluating every config's nodeSelector against the node's labels. The same CIDR
// contributed by more than one matching config is dropped entirely (CFP CIDR-conflict
// semantics). It returns nil if the node matches no config.
func resolveNode(nodeName string, nodeLabels map[string]string, configs []*v2alpha1.CiliumVTEPConfig, logger *slog.Logger) *nodeResolution {
	var res *nodeResolution
	// source maps a normalized CIDR to the name of the config that first contributed it,
	// so a conflict log can name both offending configs.
	source := make(map[string]string)

	for _, cfg := range configs {
		// Selectors are pre-validated by reconcile(); a parse error here would be a
		// programming error, so treat it defensively (skip) but it should not occur.
		selector, err := selectorForConfig(cfg)
		if err != nil {
			logger.Warn("Invalid nodeSelector in CiliumVTEPConfig, skipping",
				logfields.Name, cfg.Name,
				logfields.Error, err)
			continue
		}
		if !selector.Matches(slim_labels.Set(nodeLabels)) {
			continue
		}

		if res == nil {
			res = &nodeResolution{
				endpoints: make(map[string]v2alpha1.VTEPEndpoint),
				conflicts: sets.New[string](),
			}
		}
		res.owners = append(res.owners, cfg)

		for _, ep := range cfg.Spec.VTEPEndpoints {
			key, err := normalizeCIDR(ep.CIDR)
			if err != nil {
				logger.Warn("Invalid CIDR in CiliumVTEPConfig, skipping endpoint",
					logfields.Name, cfg.Name,
					logfields.CIDR, ep.CIDR,
					logfields.Error, err)
				continue
			}
			if res.conflicts.Has(key) {
				continue
			}
			if _, exists := res.endpoints[key]; exists {
				// Same CIDR contributed by more than one matching config:
				// neither is applied (CFP CIDR-conflict semantics).
				delete(res.endpoints, key)
				res.conflicts.Insert(key)
				logger.Error("VTEP CIDR conflict between matching CiliumVTEPConfigs; dropping the conflicting endpoint (neither config is applied to this node)",
					logfields.Node, nodeName,
					logfields.CIDR, key,
					logfields.Config, source[key]+","+cfg.Name)
				continue
			}
			res.endpoints[key] = ep
			source[key] = cfg.Name
		}
	}

	return res
}

// selectorForConfig returns the label selector for a config. A nil nodeSelector
// matches every node.
func selectorForConfig(cfg *v2alpha1.CiliumVTEPConfig) (slim_labels.Selector, error) {
	if cfg.Spec.NodeSelector == nil {
		return slim_labels.Everything(), nil
	}
	return slim_meta_v1.LabelSelectorAsSelector(cfg.Spec.NodeSelector)
}

// normalizeCIDR returns the canonical network form of a CIDR string
// (e.g. "10.1.1.5/24" -> "10.1.1.0/24"), which is the BPF LPM map key.
func normalizeCIDR(s string) (string, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return "", err
	}
	return ipNet.String(), nil
}

// sortedEndpoints returns the endpoints sorted by name for deterministic output.
func sortedEndpoints(m map[string]v2alpha1.VTEPEndpoint) []v2alpha1.VTEPEndpoint {
	out := make([]v2alpha1.VTEPEndpoint, 0, len(m))
	for _, ep := range m {
		out = append(out, ep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ownerReferences builds non-controller owner references to all matching configs,
// so the per-node object is cascade-garbage-collected once every owning config is
// deleted (the operator's explicit GC handles the no-longer-matching case).
func ownerReferences(owners []*v2alpha1.CiliumVTEPConfig) []metav1.OwnerReference {
	if len(owners) == 0 {
		return nil
	}
	// Deduplicate by UID and sort by name for deterministic output.
	seen := sets.New[string]()
	sorted := make([]*v2alpha1.CiliumVTEPConfig, 0, len(owners))
	for _, o := range owners {
		if seen.Has(string(o.UID)) {
			continue
		}
		seen.Insert(string(o.UID))
		sorted = append(sorted, o)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	refs := make([]metav1.OwnerReference, 0, len(sorted))
	for _, o := range sorted {
		refs = append(refs, metav1.OwnerReference{
			APIVersion:         v2alpha1.SchemeGroupVersion.String(),
			Kind:               v2alpha1.CVTEPKindDefinition,
			Name:               o.Name,
			UID:                o.UID,
			BlockOwnerDeletion: ptr.To(false),
		})
	}
	return refs
}

// ownerRefsEqual compares two owner-reference slices by (Name, UID), order-insensitive.
func ownerRefsEqual(a, b []metav1.OwnerReference) bool {
	if len(a) != len(b) {
		return false
	}
	set := func(refs []metav1.OwnerReference) sets.Set[string] {
		s := sets.New[string]()
		for _, r := range refs {
			s.Insert(r.Name + "/" + string(r.UID))
		}
		return s
	}
	return set(a).Equal(set(b))
}
