// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func (b *BGPResourceManager) reconcileBGPClusterConfigs(ctx context.Context) error {
	var err error
	for _, config := range b.clusterConfigStore.List() {
		rcErr := b.reconcileBGPClusterConfig(ctx, config)
		if rcErr != nil {
			b.metrics.BGPClusterConfigErrorCount.WithLabelValues(config.Name).Inc()
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

	// Errors
	var errs error

	for _, node := range b.ciliumNodeStore.List() {
		if !nodeSelector.Matches(slim_labels.Set(node.Labels)) {
			continue
		}

		// Record selected node for later use
		matchingNodes.Insert(node.Name)

		// Find node config for this node
		oldNodeConfig, oldNodeConfigExists, err := b.nodeConfigStore.GetByKey(resource.Key{Name: node.Name})
		if err != nil {
			errs = errors.Join(errs, err)
			continue
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
			errs = errors.Join(errs, err)
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
				BGPInstances: toNodeBGPInstance(config.Spec.BGPInstances, overrideInstances),
			},
		}

		switch {
		case !oldNodeConfigExists:
			// Create a new NodeConfig the new spec
			if _, err := b.nodeConfigClient.Create(ctx, newNodeConfig, meta_v1.CreateOptions{}); err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			b.logger.Debug("Creating a new CiliumBGPNodeConfig", "node_config", newNodeConfig.Name, "cluster_config", config.Name)

		case oldNodeConfigExists && !oldNodeConfig.Spec.DeepEqual(&newNodeConfig.Spec):
			// Update existing NodeConfig with the new spec
			oldNodeConfig.Spec = newNodeConfig.Spec
			if _, err := b.nodeConfigClient.Update(ctx, oldNodeConfig, meta_v1.UpdateOptions{}); err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			b.logger.Debug("Updating an existing CiliumBGPNodeConfig", "node_config", oldNodeConfig.Name, "cluster_config", config.Name)
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
		if err := b.nodeConfigClient.Delete(ctx, nodeConfig.Name, meta_v1.DeleteOptions{}); err != nil {
			if k8s_errors.IsNotFound(err) {
				continue
			}
			errs = errors.Join(err)
			continue
		}
		b.logger.Debug("Deleted BGP node config", "node_config", nodeConfig.Name, "cluster_config", config.Name)
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

func toNodeBGPInstance(clusterBGPInstances []v2.CiliumBGPInstance, overrideBGPInstances []v2.CiliumBGPNodeConfigInstanceOverride) []v2.CiliumBGPNodeInstance {
	var res []v2.CiliumBGPNodeInstance

	for _, clusterBGPInstance := range clusterBGPInstances {
		nodeBGPInstance := v2.CiliumBGPNodeInstance{
			Name:      clusterBGPInstance.Name,
			LocalASN:  clusterBGPInstance.LocalASN,
			LocalPort: clusterBGPInstance.LocalPort,
		}

		// find BGPResourceManager global override for this instance
		var override v2.CiliumBGPNodeConfigInstanceOverride
		for _, overrideBGPInstance := range overrideBGPInstances {
			if overrideBGPInstance.Name == clusterBGPInstance.Name {
				nodeBGPInstance.RouterID = overrideBGPInstance.RouterID
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
