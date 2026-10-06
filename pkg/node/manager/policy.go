// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

// updatePolicy groups the node-update policy while it continues to use the
// Manager-owned state. Later patches will make this policy the Writer policy.
type updatePolicy struct {
	manager *manager
}

var _ node.UpdatePolicy = &updatePolicy{}

// Upsert implements [node.UpdatePolicy].
func (p *updatePolicy) Upsert(n *nodeTypes.Node) (publish bool) {
	m := p.manager
	m.logger.Info(
		"Node updated",
		logfields.ClusterName, n.Cluster,
		logfields.NodeName, n.Name,
		logfields.SPI, n.EncryptionKey,
	)
	if m.logger.Enabled(context.Background(), slog.LevelDebug) {
		m.logger.Debug(
			fmt.Sprintf("Received node update event from %s", n.Source),
			logfields.Node, n,
		)
	}

	nodeIdentifier := n.Identity()
	dpUpdate := true
	var nodeIP netip.Addr
	if nIP := n.GetNodeIP(m.underlay == tunnel.IPv6); nIP.IsValid() {
		// GH-24829: Support IPv6-only nodes.
		nodeIP = nIP
	}

	resource := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindNode, "", n.Name)
	nodeLabels := m.nodeIdentityLabels(*n)

	var nodeIPsAdded, healthIPsAdded, ingressIPsAdded, podCIDRsAdded []netip.Prefix

	for _, address := range n.IPAddresses {
		prefix := netip.PrefixFrom(address.IP.Addr, address.IP.BitLen())
		var prefixCluster cmtypes.PrefixCluster
		if address.Type == addressing.NodeCiliumInternalIP {
			prefixCluster = cmtypes.PrefixClusterFrom(prefix, m.prefixClusterMutatorFn(n)...)
		} else {
			prefixCluster = cmtypes.NewLocalPrefixCluster(prefix)
		}

		var tunnelIP netip.Addr
		if m.nodeAddressHasTunnelIP(address) {
			tunnelIP = nodeIP
		}

		var key uint8
		if m.nodeAddressHasEncryptKey() {
			key = n.EncryptionKey
		}

		endpointFlags := ipcacheTypes.EndpointFlags{}
		if n.Cluster != m.clusterInfo.Name {
			endpointFlags.SetRemoteCluster(true)
		}

		// We expect the node manager to have a source of either Kubernetes,
		// CustomResource, or KVStore. Prioritize the KVStore source over the
		// rest as it is the strongest source, i.e. only trigger datapath
		// updates if the information we receive takes priority.
		//
		// There are two exceptions to the rules above:
		// * kube-apiserver entries - in that case,
		//   we still want to inform subscribers about changes in auxiliary
		//   data such as for example the health endpoint.
		// * CiliumInternal IP addresses that match configured local router IP.
		//   In that case, we still want to inform subscribers about a new node
		//   even when IP addresses may seem repeated across the nodes.
		existing := m.ipcache.GetMetadataSourceByPrefix(prefixCluster)
		overwrite := source.AllowOverwrite(existing, n.Source)
		if !overwrite && existing != source.KubeAPIServer &&
			!(address.Type == addressing.NodeCiliumInternalIP && m.conf.IsLocalRouterIP(address.IP.Addr)) {
			dpUpdate = false
		}

		// Always associate the prefix with metadata, even though this may not
		// end up in an ipcache entry.
		m.ipcache.UpsertMetadata(prefixCluster, n.Source, resource,
			nodeLabels,
			ipcacheTypes.TunnelPeer{Addr: tunnelIP},
			ipcacheTypes.EncryptKey(key),
			endpointFlags)
		nodeIPsAdded = append(nodeIPsAdded, prefixCluster.AsPrefix())
	}

	// Add the remote node's Pod CIDRs as fallback entries into IPCache with
	// the nodeIP as the tunnel endpoint (no tunnel endpoint fallback is needed
	// for the local node).
	if !n.IsLocal() {
		ipv4PodCIDRs := n.GetIPv4AllocCIDRs()
		ipv6PodCIDRs := n.GetIPv6AllocCIDRs()

		mu := make([]ipcache.MU, 0, len(ipv4PodCIDRs)+len(ipv6PodCIDRs))
		for entry := range m.podCIDREntries(n.Source, resource, m.cidrsToPrefixesCluster(n, ipv4PodCIDRs...), nodeIP, n.EncryptionKey) {
			mu = append(mu, entry)
			podCIDRsAdded = append(podCIDRsAdded, entry.Prefix.AsPrefix())
		}
		for entry := range m.podCIDREntries(n.Source, resource, m.cidrsToPrefixesCluster(n, ipv6PodCIDRs...), nodeIP, n.EncryptionKey) {
			mu = append(mu, entry)
			podCIDRsAdded = append(podCIDRsAdded, entry.Prefix.AsPrefix())
		}
		m.ipcache.UpsertMetadataBatch(mu...)
	}

	for _, address := range []netip.Addr{n.IPv4HealthIP.Addr, n.IPv6HealthIP.Addr} {
		prefix := netip.PrefixFrom(address, address.BitLen())
		if !prefix.IsValid() {
			continue
		}

		prefixCluster := cmtypes.PrefixClusterFrom(prefix, m.prefixClusterMutatorFn(n)...)

		if !source.AllowOverwrite(m.ipcache.GetMetadataSourceByPrefix(prefixCluster), n.Source) {
			dpUpdate = false
		}

		m.ipcache.UpsertMetadata(prefixCluster, n.Source, resource,
			labels.LabelHealth,
			ipcacheTypes.TunnelPeer{Addr: nodeIP},
			m.endpointEncryptionKey(n))
		healthIPsAdded = append(healthIPsAdded, prefixCluster.AsPrefix())
	}

	for _, address := range []netip.Addr{n.IPv4IngressIP.Addr, n.IPv6IngressIP.Addr} {
		prefix := netip.PrefixFrom(address, address.BitLen())
		if !prefix.IsValid() {
			continue
		}

		prefixCluster := cmtypes.PrefixClusterFrom(prefix, m.prefixClusterMutatorFn(n)...)

		if !source.AllowOverwrite(m.ipcache.GetMetadataSourceByPrefix(prefixCluster), n.Source) {
			dpUpdate = false
		}

		m.ipcache.UpsertMetadata(prefixCluster, n.Source, resource,
			labels.LabelIngress,
			ipcacheTypes.TunnelPeer{Addr: nodeIP},
			m.endpointEncryptionKey(n))
		ingressIPsAdded = append(ingressIPsAdded, prefixCluster.AsPrefix())
	}

	m.mutex.Lock()
	entry, oldNodeExists := m.nodes[nodeIdentifier]
	if oldNodeExists {
		m.metrics.EventsReceived.WithLabelValues("update", string(n.Source)).Inc()

		if !source.AllowOverwrite(entry.node.Source, n.Source) {
			// Done; skip node-handler updates and label injection
			// triggers below. Includes case where the local host
			// was discovered locally and then is subsequently
			// updated by the k8s watcher.
			m.mutex.Unlock()
			return
		}

		entry.mutex.Lock()
		m.mutex.Unlock()
		oldNode := entry.node
		entry.node = *n
		if dpUpdate {
			var errs error
			m.Iter(func(nh node.Handler) {
				if err := nh.NodeUpdate(oldNode, entry.node); err != nil {
					m.logger.Error(
						"Failed to handle node update event while applying handler. Cilium may be have degraded functionality. See error message for details.",
						logfields.Error, err,
						logfields.Handler, nh.Name(),
						logfields.Node, entry.node.Name,
					)
					errs = errors.Join(errs, err)
				}
			})

			hr := m.health.NewScope("nodes-update")
			if errs != nil {
				hr.Degraded("Failed to update nodes", errs)
			} else {
				hr.OK("Node updates successful")
			}
		}

		m.removeNodeFromIPCache(
			oldNode,
			resource,
			nodeIPsAdded,
			healthIPsAdded,
			ingressIPsAdded,
			podCIDRsAdded,
		)

		entry.mutex.Unlock()
	} else {
		m.metrics.EventsReceived.WithLabelValues("add", string(n.Source)).Inc()
		m.metrics.NumNodes.Inc()

		entry = &nodeEntry{node: *n}
		entry.mutex.Lock()
		m.nodes[nodeIdentifier] = entry
		m.mutex.Unlock()
		var errs error
		if dpUpdate {
			m.Iter(func(nh node.Handler) {
				if err := nh.NodeAdd(entry.node); err != nil {
					m.logger.Error(
						"Failed to handle node update event while applying handler. Cilium may be have degraded functionality. See error message for details.",
						logfields.Error, err,
						logfields.Handler, nh.Name(),
						logfields.Node, entry.node.Name,
					)
					errs = errors.Join(errs, err)
				}
			})
		}
		entry.mutex.Unlock()
		hr := m.health.NewScope("nodes-add")
		if errs != nil {
			hr.Degraded("Failed to add nodes", errs)
		} else {
			hr.OK("Node adds successful")
		}

	}
	return dpUpdate
}

// Delete implements [node.UpdatePolicy].
func (p *updatePolicy) Delete(src source.Source, nodeIdentifier nodeTypes.Identity) {
	m := p.manager
	m.logger.Info(
		"Node deleted",
		logfields.ClusterName, nodeIdentifier.Cluster,
		logfields.NodeName, nodeIdentifier.Name,
	)
	m.logger.Debug(
		"Received node delete event",
		logfields.Source, src,
	)

	m.metrics.EventsReceived.WithLabelValues("delete", string(src)).Inc()

	m.mutex.Lock()
	entry, oldNodeExists := m.nodes[nodeIdentifier]
	if !oldNodeExists {
		m.mutex.Unlock()
		return
	}
	n := entry.node

	// If the source is Kubernetes and the node is the node we are running on
	// Kubernetes is giving us a hint it is about to delete our node. Close down
	// the agent gracefully in this case.
	if src != entry.node.Source {
		m.mutex.Unlock()
		if entry.node.IsLocal() && src == source.Kubernetes {
			m.logger.Debug("Kubernetes is deleting local node, close manager")
			m.Stop(context.Background())
		} else {
			m.logger.Debug(
				"Ignoring delete event of node",
				logfields.Name, nodeIdentifier.Name,
				logfields.Source, src,
				logfields.NodeOwner, entry.node.Source,
			)
		}
		return
	}

	resource := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindNode, "", n.Name)
	m.removeNodeFromIPCache(entry.node, resource, nil, nil, nil, nil)
	m.metrics.NumNodes.Dec()

	entry.mutex.Lock()
	delete(m.nodes, nodeIdentifier)
	m.mutex.Unlock()
	var errs error
	m.Iter(func(nh node.Handler) {
		if err := nh.NodeDelete(n); err != nil {
			m.logger.Error(
				"Failed to handle node delete event while applying handler. Cilium may be have degraded functionality.",
				logfields.Error, err,
				logfields.Handler, nh.Name(),
				logfields.Node, n.Name,
			)
			errs = errors.Join(errs, err)
		}
	})
	entry.mutex.Unlock()

	hr := m.health.NewScope("nodes-delete")
	if errs != nil {
		hr.Degraded("Failed to delete nodes", errs)
	} else {
		hr.OK("Node deletions successful")
	}
}
