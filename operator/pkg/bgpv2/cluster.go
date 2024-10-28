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

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (b *BGPResourceManager) reconcileBGPClusterConfigs(ctx context.Context) error {
	var err error
	for _, config := range b.clusterConfigStore.List() {
		rcErr := b.reconcileBGPClusterConfig(ctx, config)
		if rcErr != nil {
			err = errors.Join(err, rcErr)
		}
	}
	return err
}

func (b *BGPResourceManager) reconcileBGPClusterConfig(ctx context.Context, config *v2alpha1.CiliumBGPClusterConfig) error {
	// get nodes which match node selector for given cluster config
	matchingNodes, conflictingClusterConfigs, err := b.getMatchingNodes(config)
	if err != nil {
		return err
	}

	// update node configs for matched nodes
	for nodeRef := range matchingNodes {
		upsertErr := b.upsertNodeConfig(ctx, config, nodeRef)
		if upsertErr != nil {
			err = errors.Join(err, upsertErr)
		}
	}

	// delete node configs for this cluster that are not in the matching nodes
	dErr := b.deleteStaleNodeConfigs(ctx, matchingNodes, config)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	// Collect the missing peerConfig references
	missingPCs := b.missingPeerConfigs(config)

	// Update ClusterConfig conditions
	updateStatus := false
	if changed := b.updateNoMatchingNodeCondition(config, len(matchingNodes) == 0); changed {
		updateStatus = true
	}
	if changed := b.updateMissingPeerConfigsCondition(config, missingPCs); changed {
		updateStatus = true
	}
	if changed := b.updateConflictingClusterConfigsCondition(config, conflictingClusterConfigs); changed {
		updateStatus = true
	}

	// Sort conditions to the stable order
	slices.SortStableFunc(config.Status.Conditions, func(a, b meta_v1.Condition) int {
		return strings.Compare(a.Type, b.Type)
	})

	// Call API only when there's a condition change
	if updateStatus {
		_, uErr := b.clientset.CiliumV2alpha1().CiliumBGPClusterConfigs().UpdateStatus(ctx, config, meta_v1.UpdateOptions{})
		if uErr != nil {
			err = errors.Join(err, uErr)
		}
	}

	return err
}

// missingPeerConfigs returns a CiliumBGPPeerConfig which is referenced from
// the ClusterConfig, but doesn't exist. The returned slice is sorted and
// deduplicated for output stability.
func (b *BGPResourceManager) missingPeerConfigs(config *v2alpha1.CiliumBGPClusterConfig) []string {
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

func (b *BGPResourceManager) updateConflictingClusterConfigsCondition(config *v2alpha1.CiliumBGPClusterConfig, conflictingClusterConfigs sets.Set[string]) bool {
	cond := meta_v1.Condition{
		Type:               v2alpha1.BGPClusterConfigConditionConflictingClusterConfigs,
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

func (b *BGPResourceManager) updateMissingPeerConfigsCondition(config *v2alpha1.CiliumBGPClusterConfig, missingPCs []string) bool {
	cond := meta_v1.Condition{
		Type:               v2alpha1.BGPClusterConfigConditionMissingPeerConfigs,
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

func (b *BGPResourceManager) updateNoMatchingNodeCondition(config *v2alpha1.CiliumBGPClusterConfig, noMatchingNode bool) bool {
	cond := meta_v1.Condition{
		Type:               v2alpha1.BGPClusterConfigConditionNoMatchingNode,
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

func (b *BGPResourceManager) upsertNodeConfig(ctx context.Context, config *v2alpha1.CiliumBGPClusterConfig, nodeName string) error {
	prev, exists, err := b.nodeConfigStore.GetByKey(resource.Key{Name: nodeName})
	if err != nil {
		return err
	}

	// find node overrides for given node
	var overrideInstances []v2alpha1.CiliumBGPNodeConfigInstanceOverride
	overrides := b.nodeConfigOverrideStore.List()
	for _, override := range overrides {
		if override.Name == nodeName {
			overrideInstances = override.Spec.BGPInstances
			break
		}
	}

	// create new config
	nodeConfig := &v2alpha1.CiliumBGPNodeConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: nodeName,
			OwnerReferences: []meta_v1.OwnerReference{
				{
					APIVersion: v2alpha1.SchemeGroupVersion.String(),
					Kind:       v2alpha1.BGPCCKindDefinition,
					Name:       config.GetName(),
					UID:        config.GetUID(),
				},
			},
		},
		Spec: v2alpha1.CiliumBGPNodeSpec{
			BGPInstances: toNodeBGPInstance(config.Spec.BGPInstances, overrideInstances),
		},
	}

	switch {
	case exists && prev.Spec.DeepEqual(&nodeConfig.Spec):
		return nil
	case exists:
		// reinitialize spec and status fields
		prev.Spec = nodeConfig.Spec
		_, err = b.nodeConfigClient.Update(ctx, prev, meta_v1.UpdateOptions{})
	default:
		_, err = b.nodeConfigClient.Create(ctx, nodeConfig, meta_v1.CreateOptions{})
		if err != nil && k8s_errors.IsAlreadyExists(err) {
			// local store is not yet updated, but API server has the resource. Get resource from API server
			// to compare spec.
			prev, err = b.nodeConfigClient.Get(ctx, nodeConfig.Name, meta_v1.GetOptions{})
			if err != nil {
				return err
			}

			// if prev already exist and spec is different, update it
			if !prev.Spec.DeepEqual(&nodeConfig.Spec) {
				prev.Spec = nodeConfig.Spec
				_, err = b.nodeConfigClient.Update(ctx, prev, meta_v1.UpdateOptions{})
			} else {
				// idempotent change, skip
				return nil
			}
		}
	}

	b.logger.Debug("Upserting BGP node config", "node_ config", nodeConfig.Name, "cluster_config", config.Name)

	return err
}

func toNodeBGPInstance(clusterBGPInstances []v2alpha1.CiliumBGPInstance, overrideBGPInstances []v2alpha1.CiliumBGPNodeConfigInstanceOverride) []v2alpha1.CiliumBGPNodeInstance {
	var res []v2alpha1.CiliumBGPNodeInstance

	for _, clusterBGPInstance := range clusterBGPInstances {
		nodeBGPInstance := v2alpha1.CiliumBGPNodeInstance{
			Name:     clusterBGPInstance.Name,
			LocalASN: clusterBGPInstance.LocalASN,
		}

		// find BGPResourceManager global override for this instance
		var override v2alpha1.CiliumBGPNodeConfigInstanceOverride
		for _, overrideBGPInstance := range overrideBGPInstances {
			if overrideBGPInstance.Name == clusterBGPInstance.Name {
				nodeBGPInstance.RouterID = overrideBGPInstance.RouterID
				nodeBGPInstance.LocalPort = overrideBGPInstance.LocalPort
				override = overrideBGPInstance
				break
			}
		}

		for _, clusterBGPInstancePeer := range clusterBGPInstance.Peers {
			nodePeer := v2alpha1.CiliumBGPNodePeer{
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

// getMatchingNodes returns a map of node names that match the given cluster config's node selector.
func (b *BGPResourceManager) getMatchingNodes(config *v2alpha1.CiliumBGPClusterConfig) (sets.Set[string], sets.Set[string], error) {
	labelSelector, err := slim_meta_v1.LabelSelectorAsSelector(config.Spec.NodeSelector)
	if err != nil {
		return nil, nil, err
	}

	// find nodes that match the cluster config's node selector
	matchingNodes := sets.New[string]()

	// find ClusterConfigs that has the conflicting node selector
	conflictingClusterConfigs := sets.New[string]()

	for _, n := range b.ciliumNodeStore.List() {
		// nil node selector means match all nodes
		if config.Spec.NodeSelector == nil || labelSelector.Matches(slim_labels.Set(n.Labels)) {
			nc, exists, err := b.nodeConfigStore.GetByKey(resource.Key{Name: n.Name})
			if err != nil {
				b.logger.Error(fmt.Sprintf("skipping node %s", n.Name), logfields.Error, err)
				continue
			}

			if exists && !isOwner(nc.GetOwnerReferences(), config) {
				// Node is already selected by another cluster config. Figure out which one.
				ownerName := ownerClusterConfigName(nc.GetOwnerReferences())
				conflictingClusterConfigs.Insert(ownerName)
				continue
			}

			matchingNodes.Insert(n.Name)
		}
	}

	return matchingNodes, conflictingClusterConfigs, nil
}

// deleteStaleNodeConfigs deletes node configs that are not in the expected list for given cluster.
// TODO there might be a race where stale node configs are not detected and deleted. Check issue #30320 for more details.
func (b *BGPResourceManager) deleteStaleNodeConfigs(ctx context.Context, expectedNodes sets.Set[string], config *v2alpha1.CiliumBGPClusterConfig) error {
	var err error
	for _, existingNode := range b.nodeConfigStore.List() {
		if expectedNodes.Has(existingNode.Name) || !isOwner(existingNode.GetOwnerReferences(), config) {
			continue
		}

		dErr := b.nodeConfigClient.Delete(ctx, existingNode.Name, meta_v1.DeleteOptions{})
		if dErr != nil && k8s_errors.IsNotFound(dErr) {
			continue
		} else if dErr != nil {
			err = errors.Join(err, dErr)
		} else {
			b.logger.Debug("Deleting BGP node config", "node_config", existingNode.Name,
				"cluster_config", config.Name)
		}
	}
	return err
}

// isOwner checks if the expected is present in owners list.
func isOwner(owners []meta_v1.OwnerReference, config *v2alpha1.CiliumBGPClusterConfig) bool {
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
		if owner.APIVersion == v2alpha1.SchemeGroupVersion.String() && owner.Kind == v2alpha1.BGPCCKindDefinition {
			return owner.Name
		}
	}
	return ""
}
