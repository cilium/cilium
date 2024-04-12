// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// NodeAdd is called when a node is discovered for the first time.
func (a *Agent) NodeAdd(newNode nodeTypes.Node) error {
	return a.nodeUpsert(newNode)
}

// NmdeUpdate is called when a node definition changes. Both the old
// and new node definition is provided. NodeUpdate() is never called
// before NodeAdd() is called for a particular node.
func (a *Agent) NodeUpdate(_, newNode nodeTypes.Node) error {
	return a.nodeUpsert(newNode)
}

// NodeDelete is called after a node has been deleted
func (a *Agent) NodeDelete(node nodeTypes.Node) error {
	if node.IsLocal() {
		return nil
	}

	return a.DeletePeer(node.Fullname())
}

// AllNodeValidateImplementation is called to validate the implementation of
// all nodes in the datapath.
func (a *Agent) AllNodeValidateImplementation() {
}

// NodeValidateImplementation is called to validate the implementation of
// the node in the datapath. This function is intended to be run on an
// interval to ensure that the datapath is consistently converged.
func (a *Agent) NodeValidateImplementation(node nodeTypes.Node) error {
	return a.nodeUpsert(node)
}

func (a *Agent) nodeUpsert(node nodeTypes.Node) error {
	externalNodeLabelValue, ok := node.Labels[wgTypes.ExternalNodeLabel]
	isExternalNode := ok && externalNodeLabelValue == "true"

	if (node.IsLocal() && !isExternalNode) || node.WireguardPubKey == "" {
		return nil
	}

	if node.IsLocal() {
		if isExternalNode != a.wgExternal {
			log.Infof("switching wireguard agent mode: external node = %v", isExternalNode)
			a.wgExternal = isExternalNode
		}
		return nil // local node doesn't have a peer entry
	}

	newAddrs := peerAddresses{
		NodeIPv4:            node.GetNodeIP(false),
		NodeIPv6:            node.GetNodeIP(true),
		ExternalIPv4:        node.GetExternalIP(false),
		ExternalIPv6:        node.GetExternalIP(true),
		UseExternalEndpoint: isExternalNode || a.wgExternal,
	}

	if err := a.UpdatePeer(node.Fullname(), node.WireguardPubKey, newAddrs); err != nil {
		log.WithError(err).
			WithField(logfields.NodeName, node.Fullname()).
			Warning("Failed to update WireGuard configuration for peer")
	}

	return nil
}

// NodeConfigurationChanged is called when the local node configuration
// has changed
func (a *Agent) NodeConfigurationChanged(config datapath.LocalNodeConfiguration) error { return nil }
