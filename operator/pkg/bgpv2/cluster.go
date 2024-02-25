// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
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
	matchingNodes, err := b.getMatchingNodes(config.Spec.NodeSelector, config.Name)
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
	dErr := b.deleteStaleNodeConfigs(ctx, matchingNodes, config.Name)
	if dErr != nil {
		err = errors.Join(err, dErr)
	}

	return err
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
		if override.Spec.NodeRef == nodeName {
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
					APIVersion: slim_core_v1.SchemeGroupVersion.String(),
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

	b.logger.WithFields(logrus.Fields{
		"node config":    nodeConfig.Name,
		"cluster config": config.Name,
	}).Debug("Upserting BGP node config")

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
func (b *BGPResourceManager) getMatchingNodes(nodeSelector *slim_meta_v1.LabelSelector, configName string) (sets.Set[string], error) {
	labelSelector, err := slim_meta_v1.LabelSelectorAsSelector(nodeSelector)
	if err != nil {
		return nil, err
	}

	// find nodes that match the cluster config's node selector
	matchingNodes := sets.New[string]()

	for _, n := range b.ciliumNodeStore.List() {
		// nil node selector means match all nodes
		if nodeSelector == nil || labelSelector.Matches(slim_labels.Set(n.Labels)) {
			err := b.validNodeSelection(n, configName)
			if err != nil {
				b.logger.WithError(err).Errorf("skipping node %s", n.Name)
				continue
			}
			matchingNodes.Insert(n.Name)
		}
	}

	return matchingNodes, nil
}

// deleteStaleNodeConfigs deletes node configs that are not in the expected list for given cluster.
// TODO there might be a race where stale node configs are not detected and deleted. Check issue #30320 for more details.
func (b *BGPResourceManager) deleteStaleNodeConfigs(ctx context.Context, expectedNodes sets.Set[string], clusterRef string) error {
	var err error
	for _, existingNode := range b.nodeConfigStore.List() {
		if expectedNodes.Has(existingNode.Name) || !IsOwner(existingNode.GetOwnerReferences(), clusterRef) {
			continue
		}

		dErr := b.nodeConfigClient.Delete(ctx, existingNode.Name, meta_v1.DeleteOptions{})
		if dErr != nil && k8s_errors.IsNotFound(dErr) {
			continue
		} else if dErr != nil {
			err = errors.Join(err, dErr)
		} else {
			b.logger.WithFields(logrus.Fields{
				"node config":    existingNode.Name,
				"cluster config": clusterRef,
			}).Debug("Deleting BGP node config")
		}
	}
	return err
}

// validNodeSelection checks if the node is already present in another cluster config.
func (b *BGPResourceManager) validNodeSelection(node *cilium_api_v2.CiliumNode, expectedOwnerName string) error {
	existingBGPNodeConfig, exists, err := b.nodeConfigStore.GetByKey(resource.Key{Name: node.Name})
	if err != nil {
		return err
	}

	if exists && !IsOwner(existingBGPNodeConfig.GetOwnerReferences(), expectedOwnerName) {
		return fmt.Errorf("BGPResourceManager node config %s already exist", existingBGPNodeConfig.Name)
	}

	return nil
}

// IsOwner checks if the expected is present in owners list.
func IsOwner(owners []meta_v1.OwnerReference, expected string) bool {
	for _, owner := range owners {
		if owner.Name == expected {
			return true
		}
	}
	return false
}
