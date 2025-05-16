// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/ipalloc"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

type RouterIDKey struct {
	NodeName     string
	InstanceName string
}

func (b *BGPResourceManager) reconcileBGPClusterConfigs(ctx context.Context) error {
	var err error
	configs := b.clusterConfigStore.List()
	// Have to clean the routerIDMap while clusterconfig is empty
	// because the NodeConfig are deleted by kube garbage collection
	if len(configs) == 0 && b.bgpRouterIDIPPoolEnabled {
		// Clear all router ID allocations when there are no BGP configs
		if err := b.freeRouterID("", nil); err != nil {
			return err
		}
	}

	for _, config := range configs {
		rcErr := b.reconcileBGPClusterConfig(ctx, config)
		if rcErr != nil {
			b.metrics.ReconcileErrorsTotal.WithLabelValues(v2.BGPCCKindDefinition, config.Name).Inc()
			err = errors.Join(err, rcErr)
		}
	}
	return err
}

func (b *BGPResourceManager) reconcileBGPClusterConfig(ctx context.Context, config *v2.CiliumBGPClusterConfig) error {
	var errs error

	matchingNodes, conflictingClusterConfigs, err := b.upsertNodeConfigs(ctx, config)
	if err != nil {
		return err
	}
	if err := b.deleteNodeConfigs(ctx, matchingNodes, config); err != nil {
		errs = errors.Join(err)
	}

	updateStatus := false
	if b.enableStatusReporting {
		// Collect the missing peerConfig references
		missingPCs := b.missingPeerConfigs(config)

		// Update ClusterConfig conditions
		if changed := b.updateNoMatchingNodeCondition(config, len(matchingNodes) == 0); changed {
			updateStatus = true
		}
		if changed := b.updateMissingPeerConfigsCondition(config, missingPCs); changed {
			updateStatus = true
		}
		if changed := b.updateConflictingClusterConfigsCondition(config, conflictingClusterConfigs); changed {
			updateStatus = true
		}
	} else {
		// If the status reporting is disabled, we need to ensure all
		// conditions managed by this controller are removed.
		// Otherwise, users may see the stale conditions which were
		// reported previously.
		for _, cond := range v2.AllBGPClusterConfigConditions {
			if removed := meta.RemoveStatusCondition(&config.Status.Conditions, cond); removed {
				updateStatus = true
			}
		}
	}

	// Call API only when there's a condition change
	if updateStatus {
		// Sort conditions to the stable order
		slices.SortStableFunc(config.Status.Conditions, func(a, b meta_v1.Condition) int {
			return strings.Compare(a.Type, b.Type)
		})
		_, err := b.clientset.CiliumV2().CiliumBGPClusterConfigs().UpdateStatus(ctx, config, meta_v1.UpdateOptions{})
		if err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func (b *BGPResourceManager) upsertNodeConfigs(ctx context.Context, config *v2.CiliumBGPClusterConfig) (sets.Set[string], sets.Set[string], error) {
	var nodeSelector slim_labels.Selector
	var errs error
	if config.Spec.NodeSelector == nil {
		// nil selector means select all nodes
		nodeSelector = slim_labels.Everything()
	} else {
		selector, err := slim_meta_v1.LabelSelectorAsSelector(config.Spec.NodeSelector)
		if err != nil {
			return nil, nil, err
		}
		nodeSelector = selector
	}
	// Name of the nodes selected by nodeSelector
	matchingNodes := sets.New[string]()
	// Name of the ClusterConfig selecting the same node
	conflictingClusterConfigs := sets.New[string]()

	for _, node := range b.ciliumNodeStore.List() {
		bgpNode := nodeSelector.Matches(slim_labels.Set(node.Labels))
		oldNodeConfig, oldNodeConfigExists, err := b.nodeConfigStore.GetByKey(resource.Key{Name: node.Name})

		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to get node config for node %s: %w", node.Name, err))
			continue
		}
		// restore the router ID from the old NodeConfig if it exists
		if oldNodeConfigExists && b.bgpRouterIDIPPoolEnabled {
			for _, instance := range oldNodeConfig.Spec.BGPInstances {
				if instance.RouterID == nil {
					continue
				}
				routerID, err := netip.ParseAddr(*instance.RouterID)
				if err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to parse router ID for node %s: %w", node.Name, err))
					continue
				}
				key := getRouterIDKey(node.Name, instance.Name)
				_, exists := b.bgpRouterIDMap[key]

				// If we found it doesn't exist and it's a BGP node, we need to restore it from old config to map and IP pool
				// because the operator could just have been restarted
				if bgpNode && !exists {
					err := b.allocateRouterID(key, &routerID)
					if err != nil {
						errs = errors.Join(errs, fmt.Errorf("failed to restore router ID for node %s: %w", node.Name, err))
						continue
					}
				}
			}
		}
		if !bgpNode {
			continue
		}
		// Record selected node for later use
		matchingNodes.Insert(node.Name)
		// allocate router IDs for all instances for nodes and skip if already allocated(restored from old NodeConfig)
		if b.bgpRouterIDIPPoolEnabled {
			for _, instance := range config.Spec.BGPInstances {
				key := getRouterIDKey(node.Name, instance.Name)
				if _, exists := b.bgpRouterIDMap[key]; exists {
					continue
				}
				err := b.allocateRouterID(key, nil)
				if err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to allocate router ID for node and instance %s/%s: %w", node.Name, instance.Name, err))
				}
			}
		}
		// Conflict detection
		if oldNodeConfigExists && !isOwner(oldNodeConfig.OwnerReferences, config) {
			owner := ownerClusterConfigName(oldNodeConfig.OwnerReferences)
			if owner != "" {
				conflictingClusterConfigs.Insert(owner)
			}
			// Conflict detected. Skip this node.
			continue
		}

		// Find node overrides for this node
		nodeConfigOverride, nodeConfigOverrideExists, err := b.nodeConfigOverrideStore.GetByKey(resource.Key{Name: node.Name})
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to get node config override for node %s: %w", node.Name, err))
			continue
		}

		// Build a desired node config
		var overrideInstances []v2.CiliumBGPNodeConfigInstanceOverride
		if nodeConfigOverrideExists {
			overrideInstances = nodeConfigOverride.Spec.BGPInstances
		}
		newNodeConfig := &v2.CiliumBGPNodeConfig{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: node.Name,
				OwnerReferences: []meta_v1.OwnerReference{
					{
						APIVersion: v2.SchemeGroupVersion.String(),
						Kind:       v2.BGPCCKindDefinition,
						Name:       config.GetName(),
						UID:        config.GetUID(),

						// It is generally recommended to set this to the
						// reference from the controller object. Note that
						// we shouldn't rely on this field to be set (e.g.
						// don't use metav1.GetControllerOf until v1.19
						// since we might have an existing resource that
						// doesn't have this set.
						Controller: ptr.To(true),
					},
				},
			},
			Spec: v2.CiliumBGPNodeSpec{
				BGPInstances: b.toNodeBGPInstance(config.Spec.BGPInstances, overrideInstances, node.Name),
			},
		}

		switch {
		case !oldNodeConfigExists:
			// Create a new NodeConfig the new spec
			if _, err := b.nodeConfigClient.Create(ctx, newNodeConfig, meta_v1.CreateOptions{}); err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			b.logger.Debug("Creating a new CiliumBGPNodeConfig",
				types.BGPNodeConfigLogField, newNodeConfig.Name,
				types.LabelClusterConfig, config.Name,
			)

		case oldNodeConfigExists && !oldNodeConfig.Spec.DeepEqual(&newNodeConfig.Spec):
			// Update existing NodeConfig with the new spec
			oldNodeConfig.Spec = newNodeConfig.Spec
			if _, err := b.nodeConfigClient.Update(ctx, oldNodeConfig, meta_v1.UpdateOptions{}); err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			b.logger.Debug("Updating an existing CiliumBGPNodeConfig",
				types.BGPNodeConfigLogField, oldNodeConfig.Name,
				types.LabelClusterConfig, config.Name,
			)
		}

	}
	return matchingNodes, conflictingClusterConfigs, errs
}

func (b *BGPResourceManager) deleteNodeConfigs(ctx context.Context, selectedNodes sets.Set[string], config *v2.CiliumBGPClusterConfig) error {
	var errs error

	for _, nodeConfig := range b.nodeConfigStore.List() {
		if selectedNodes.Has(nodeConfig.Name) || !isOwner(nodeConfig.OwnerReferences, config) {
			continue
		}

		// If the NodeConfig is not selected by the ClusterConfig, but
		// owned by it, it is a stale NodeConfig. Delete it.
		deleteErr := b.nodeConfigClient.Delete(ctx, nodeConfig.Name, meta_v1.DeleteOptions{})

		if deleteErr != nil {
			if k8s_errors.IsNotFound(deleteErr) {
				continue
			}
			errs = errors.Join(errs, deleteErr)
			continue
		} else {
			// free the router ID from the IP pool and remove it from the map
			if b.bgpRouterIDIPPoolEnabled {
				for _, instance := range nodeConfig.Spec.BGPInstances {
					key := getRouterIDKey(nodeConfig.Name, instance.Name)
					if routerID, exists := b.bgpRouterIDMap[key]; exists {
						if freeErr := b.freeRouterID(key, routerID); freeErr != nil {
							errs = errors.Join(errs, fmt.Errorf("failed to free router ID for node and instance %s/%s: %w", nodeConfig.Name, instance.Name, freeErr))
						}
					}
				}
			}

		}
		b.logger.Debug("Deleted BGP node config",
			types.BGPNodeConfigLogField, nodeConfig.Name,
			types.LabelClusterConfig, config.Name,
		)
	}
	return errs
}

// missingPeerConfigs returns a CiliumBGPPeerConfig which is referenced from
// the ClusterConfig, but doesn't exist. The returned slice is sorted and
// deduplicated for output stability.
func (b *BGPResourceManager) missingPeerConfigs(config *v2.CiliumBGPClusterConfig) []string {
	missing := []string{}
	for _, instance := range config.Spec.BGPInstances {
		for _, peer := range instance.Peers {
			if peer.PeerConfigRef == nil {
				continue
			}

			_, exists, _ := b.peerConfigStore.GetByKey(resource.Key{Name: peer.PeerConfigRef.Name})
			if !exists {
				missing = append(missing, peer.PeerConfigRef.Name)
			}

			// Just ignore the error other than NotFound. It might
			// be a network issue, or something else, but we are
			// only interested in detecting the invalid reference
			// here.
		}
	}
	slices.Sort(missing)
	return slices.Compact(missing)
}

func (b *BGPResourceManager) updateConflictingClusterConfigsCondition(config *v2.CiliumBGPClusterConfig, conflictingClusterConfigs sets.Set[string]) bool {
	cond := meta_v1.Condition{
		Type:               v2.BGPClusterConfigConditionConflictingClusterConfigs,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "ConflictingClusterConfigs",
	}
	if conflictingClusterConfigs.Len() != 0 {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Selecting the same node(s) with ClusterConfig(s): %v", sets.List(conflictingClusterConfigs))
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (b *BGPResourceManager) updateMissingPeerConfigsCondition(config *v2.CiliumBGPClusterConfig, missingPCs []string) bool {
	cond := meta_v1.Condition{
		Type:               v2.BGPClusterConfigConditionMissingPeerConfigs,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "MissingPeerConfigs",
	}
	if len(missingPCs) != 0 {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced CiliumBGPPeerConfig(s) are missing: %v", missingPCs)
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (b *BGPResourceManager) updateNoMatchingNodeCondition(config *v2.CiliumBGPClusterConfig, noMatchingNode bool) bool {
	cond := meta_v1.Condition{
		Type:               v2.BGPClusterConfigConditionNoMatchingNode,
		Status:             meta_v1.ConditionTrue,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "NoMatchingNode",
		Message:            "No node matches spec.nodeSelector",
	}
	if !noMatchingNode {
		cond.Status = meta_v1.ConditionFalse
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (b *BGPResourceManager) toNodeBGPInstance(clusterBGPInstances []v2.CiliumBGPInstance, overrideBGPInstances []v2.CiliumBGPNodeConfigInstanceOverride, nodeName string) []v2.CiliumBGPNodeInstance {
	var res []v2.CiliumBGPNodeInstance

	for _, clusterBGPInstance := range clusterBGPInstances {
		nodeBGPInstance := v2.CiliumBGPNodeInstance{
			Name:      clusterBGPInstance.Name,
			LocalASN:  clusterBGPInstance.LocalASN,
			LocalPort: clusterBGPInstance.LocalPort,
		}
		if b.bgpRouterIDIPPoolEnabled {
			routerIDKey := getRouterIDKey(nodeName, clusterBGPInstance.Name)
			if routerID, exists := b.bgpRouterIDMap[routerIDKey]; exists {
				nodeBGPInstance.RouterID = ptr.To(routerID.String())
			}
		}
		// find BGPResourceManager global override for this instance
		var override v2.CiliumBGPNodeConfigInstanceOverride
		for _, overrideBGPInstance := range overrideBGPInstances {
			if overrideBGPInstance.Name == clusterBGPInstance.Name {
				if overrideBGPInstance.RouterID != nil {
					nodeBGPInstance.RouterID = overrideBGPInstance.RouterID
				}
				if overrideBGPInstance.LocalPort != nil {
					nodeBGPInstance.LocalPort = overrideBGPInstance.LocalPort
				}
				if overrideBGPInstance.LocalASN != nil {
					nodeBGPInstance.LocalASN = overrideBGPInstance.LocalASN
				}
				override = overrideBGPInstance
				break
			}
		}

		for _, clusterBGPInstancePeer := range clusterBGPInstance.Peers {
			nodePeer := v2.CiliumBGPNodePeer{
				Name:          clusterBGPInstancePeer.Name,
				PeerAddress:   clusterBGPInstancePeer.PeerAddress,
				PeerASN:       clusterBGPInstancePeer.PeerASN,
				PeerConfigRef: clusterBGPInstancePeer.PeerConfigRef,
				AutoDiscovery: clusterBGPInstancePeer.AutoDiscovery,
			}

			// find BGPResourceManager Peer override for this instance
			for _, overrideBGPPeer := range override.Peers {
				if overrideBGPPeer.Name == clusterBGPInstancePeer.Name {
					nodePeer.LocalAddress = overrideBGPPeer.LocalAddress
					break
				}
			}

			nodeBGPInstance.Peers = append(nodeBGPInstance.Peers, nodePeer)
		}

		res = append(res, nodeBGPInstance)
	}
	return res
}

func (b *BGPResourceManager) clearAllRouterIDs() error {
	b.bgpRouterIDMap = make(map[string]*netip.Addr)
	if b.bgpRouterIDIPPool == nil {
		return nil
	}

	start, stop := b.bgpRouterIDIPPool.Range()
	var err error
	b.bgpRouterIDIPPool, err = ipalloc.NewHashAllocator[string](start, stop, 50)
	return err
}

func (b *BGPResourceManager) freeRouterID(key string, routerID *netip.Addr) error {
	// Handle the case to clear all router IDs
	if key == "" && routerID == nil {
		return b.clearAllRouterIDs()
	}

	if key == "" {
		return fmt.Errorf("key cannot be empty when freeing a specific router ID")
	}
	if routerID == nil {
		return fmt.Errorf("routerID cannot be nil when freeing a specific router ID")
	}

	delete(b.bgpRouterIDMap, key)

	if b.bgpRouterIDIPPool == nil {
		return fmt.Errorf("bgp Router ID pool doesn't not exist")
	}

	err := b.bgpRouterIDIPPool.Free(*routerID)
	if err == nil || errors.Is(err, ipalloc.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("failed to free router ID %s: %w", routerID, err)
}

func (b *BGPResourceManager) allocateRouterID(key string, routerID *netip.Addr) error {
	if b.bgpRouterIDIPPool == nil {
		return fmt.Errorf("bgp Router ID pool doesn't exist")
	}

	var allocatedID netip.Addr
	var err error

	if routerID != nil {
		// Allocate a specific router ID
		err = b.bgpRouterIDIPPool.Alloc(*routerID, key)
		allocatedID = *routerID
	} else {
		// Allocate any available router ID
		allocatedID, err = b.bgpRouterIDIPPool.AllocAny(key)
	}

	if err != nil {
		return err
	}

	// Store the allocated router ID in the map
	b.bgpRouterIDMap[key] = ptr.To(allocatedID)
	return nil
}

// isOwner checks if the expected is present in owners list.
func isOwner(owners []meta_v1.OwnerReference, config *v2.CiliumBGPClusterConfig) bool {
	for _, owner := range owners {
		if owner.UID == config.GetUID() {
			return true
		}
	}
	return false
}

// ownerClusterConfigName returns the name of the ClusterConfig that owns the object
func ownerClusterConfigName(owners []meta_v1.OwnerReference) string {
	for _, owner := range owners {
		if owner.APIVersion == v2.SchemeGroupVersion.String() && owner.Kind == v2.BGPCCKindDefinition {
			return owner.Name
		}
	}
	return ""
}

func getRouterIDKey(nodeName, instanceName string) string {
	return fmt.Sprintf("%s/%s", nodeName, instanceName)
}
