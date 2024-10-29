// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"iter"
	"net"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ip"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/wireguard/types"
)

var NodeReconcilerCell = cell.Module(
	"ipcache-node-reconciler",
	"Reconcile IPcache on node changes",

	cell.Invoke(registerNodeReconciler),
)

type nodeOpsParams struct {
	cell.In

	DaemonConfig     *option.DaemonConfig
	DB               *statedb.DB
	Nodes            statedb.RWTable[*node.TableNode]
	ReconcilerParams reconciler.Params
	IPCache          *IPCache
}

type nodeOps struct {
	nodeOpsParams

	// prev keeps track of the last seen version of the node in order
	// to calculate the delta between them. TODO this could be minimized
	// to just keep onto relevant data. IPAddresses?
	prev map[string]*nodeTypes.Node
}

// Delete implements reconciler.Operations.
func (nh *nodeOps) Delete(ctx context.Context, txn statedb.ReadTxn, n *node.TableNode) error {
	nh.deleted(n.Name)
	return nil
}

// Prune implements reconciler.Operations.
func (nh *nodeOps) Prune(context.Context, statedb.ReadTxn, iter.Seq2[*node.TableNode, statedb.Revision]) error {
	return nil
}

// Update implements reconciler.Operations.
func (nh *nodeOps) Update(ctx context.Context, txn statedb.ReadTxn, n *node.TableNode) error {
	nh.updated(n.Node)
	return nil
}

var _ reconciler.Operations[*node.TableNode] = &nodeOps{}

func registerNodeReconciler(g job.Group, p nodeOpsParams) error {
	ops := &nodeOps{p, make(map[string]*nodeTypes.Node)}
	_, err := reconciler.Register(
		p.ReconcilerParams,
		p.Nodes,
		(*node.TableNode).Clone,
		func(n *node.TableNode, s reconciler.Status) *node.TableNode {
			n.Statuses = n.Statuses.Set("ipcache", s)
			return n
		},
		func(n *node.TableNode) reconciler.Status {
			return n.Statuses.Get("ipcache")
		},
		ops,
		nil,
	)
	return err
}

func (nh *nodeOps) nodeIdentityLabels(n *nodeTypes.Node) (nodeLabels labels.Labels, hasOverride bool) {
	nodeLabels = labels.NewFrom(labels.LabelRemoteNode)
	if n.IsLocal() {
		nodeLabels = labels.NewFrom(labels.LabelHost)
		if nh.DaemonConfig.PolicyCIDRMatchesNodes() {
			for _, address := range n.IPAddresses {
				addr, ok := netip.AddrFromSlice(address.IP)
				if ok {
					bitLen := addr.BitLen()
					if nh.DaemonConfig.EnableIPv4 && bitLen == net.IPv4len*8 ||
						nh.DaemonConfig.EnableIPv6 && bitLen == net.IPv6len*8 {
						prefix, err := addr.Prefix(bitLen)
						if err == nil {
							cidrLabels := labels.GetCIDRLabels(prefix)
							nodeLabels.MergeLabels(cidrLabels)
						}
					}
				}
			}
		}
	} else if !identity.NumericIdentity(n.NodeIdentity).IsReservedIdentity() {
		// This needs to match clustermesh-apiserver's VMManager.AllocateNodeIdentity
		nodeLabels = labels.Map2Labels(n.Labels, labels.LabelSourceK8s)
		hasOverride = true
	} else if !n.IsLocal() && option.Config.PerNodeLabelsEnabled() {
		lbls := labels.Map2Labels(n.Labels, labels.LabelSourceNode)
		filteredLbls, _ := labelsfilter.FilterNodeLabels(lbls)
		nodeLabels.MergeLabels(filteredLbls)
	}

	return nodeLabels, hasOverride
}

func (nh *nodeOps) updated(n nodeTypes.Node) {
	log.WithFields(logrus.Fields{
		logfields.ClusterName: n.Cluster,
		logfields.NodeName:    n.Name,
		logfields.SPI:         n.EncryptionKey,
	}).Info("Node updated")
	if log.Logger.IsLevelEnabled(logrus.DebugLevel) {
		log.WithField(logfields.Node, n.LogRepr()).Debugf("Received node update event from %s", n.Source)
	}

	var nodeIP netip.Addr
	if nIP := n.GetNodeIP(false); nIP != nil {
		// GH-24829: Support IPv6-only nodes.

		// Skip returning the error here because at this level, we assume that
		// the IP is valid as long as it's coming from nodeTypes.Node. This
		// object is created either from the node discovery (K8s) or from an
		// event from the kvstore.
		nodeIP, _ = netip.AddrFromSlice(nIP)
	}

	resource := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindNode, "", n.Name)
	nodeLabels, nodeIdentityOverride := nh.nodeIdentityLabels(&n)

	var nodeIPsAdded, healthIPsAdded, ingressIPsAdded []netip.Prefix

	for _, address := range n.IPAddresses {
		prefix := ip.IPToNetPrefix(address.IP)

		var tunnelIP netip.Addr
		if nh.nodeAddressHasTunnelIP(address) {
			tunnelIP = nodeIP
		}

		var key uint8
		if nh.nodeAddressHasEncryptKey() {
			key = n.EncryptionKey
		}

		lbls := nodeLabels
		// Add the CIDR labels for this node, if we allow selecting nodes by CIDR
		if nh.DaemonConfig.PolicyCIDRMatchesNodes() {
			lbls = labels.NewFrom(nodeLabels)
			lbls.MergeLabels(labels.GetCIDRLabels(prefix))
		}

		// Always associate the prefix with metadata, even though this may not
		// end up in an ipcache entry.
		nh.IPCache.UpsertMetadata(prefix, n.Source, resource,
			lbls,
			ipcacheTypes.TunnelPeer{Addr: tunnelIP},
			ipcacheTypes.EncryptKey(key))
		if nodeIdentityOverride {
			nh.IPCache.OverrideIdentity(prefix, nodeLabels, n.Source, resource)
		}
		nodeIPsAdded = append(nodeIPsAdded, prefix)
	}

	for _, address := range []net.IP{n.IPv4HealthIP, n.IPv6HealthIP} {
		healthIP := ip.IPToNetPrefix(address)
		if !healthIP.IsValid() {
			continue
		}
		nh.IPCache.UpsertMetadata(healthIP, n.Source, resource,
			labels.LabelHealth,
			ipcacheTypes.TunnelPeer{Addr: nodeIP},
			nh.endpointEncryptionKey(&n))
		healthIPsAdded = append(healthIPsAdded, healthIP)
	}

	for _, address := range []net.IP{n.IPv4IngressIP, n.IPv6IngressIP} {
		ingressIP := ip.IPToNetPrefix(address)
		if !ingressIP.IsValid() {
			continue
		}
		nh.IPCache.UpsertMetadata(ingressIP, n.Source, resource,
			labels.LabelIngress,
			ipcacheTypes.TunnelPeer{Addr: nodeIP},
			nh.endpointEncryptionKey(&n))
		ingressIPsAdded = append(ingressIPsAdded, ingressIP)
	}
	if old, exists := nh.prev[n.Name]; exists {
		nh.removeNodeFromIPCache(old, resource, nodeIPsAdded, healthIPsAdded, ingressIPsAdded)
	}
	nh.prev[n.Name] = &n
}

// removeNodeFromIPCache removes all addresses associated with oldNode from the IPCache,
// unless they are present in the nodeIPsAdded, healthIPsAdded, ingressIPsAdded lists.
// Removes ipset entry associated with oldNode if it is not present in ipsetEntries.
//
// The removal logic in this function should mirror the upsert logic in NodeUpdated.
func (nh *nodeOps) removeNodeFromIPCache(oldNode *nodeTypes.Node, resource ipcacheTypes.ResourceID,
	nodeIPsAdded, healthIPsAdded, ingressIPsAdded []netip.Prefix) {

	var oldNodeIP netip.Addr
	if nIP := oldNode.GetNodeIP(false); nIP != nil {
		// See comment in NodeUpdated().
		oldNodeIP, _ = netip.AddrFromSlice(nIP)
	}
	oldNodeLabels, oldNodeIdentityOverride := nh.nodeIdentityLabels(oldNode)

	// Delete the old node IP addresses if they have changed in this node.
	for _, address := range oldNode.IPAddresses {
		oldPrefix := ip.IPToNetPrefix(address.IP)
		if slices.Contains(nodeIPsAdded, oldPrefix) {
			continue
		}

		var oldTunnelIP netip.Addr
		if nh.nodeAddressHasTunnelIP(address) {
			oldTunnelIP = oldNodeIP
		}

		var oldKey uint8
		if nh.nodeAddressHasEncryptKey() {
			oldKey = oldNode.EncryptionKey
		}

		nh.IPCache.RemoveMetadata(oldPrefix, resource,
			oldNodeLabels,
			ipcacheTypes.TunnelPeer{Addr: oldTunnelIP},
			ipcacheTypes.EncryptKey(oldKey))
		if oldNodeIdentityOverride {
			nh.IPCache.RemoveIdentityOverride(oldPrefix, oldNodeLabels, resource)
		}
	}

	// Delete the old health IP addresses if they have changed in this node.
	for _, address := range []net.IP{oldNode.IPv4HealthIP, oldNode.IPv6HealthIP} {
		healthIP := ip.IPToNetPrefix(address)
		if !healthIP.IsValid() || slices.Contains(healthIPsAdded, healthIP) {
			continue
		}

		nh.IPCache.RemoveMetadata(healthIP, resource,
			labels.LabelHealth,
			ipcacheTypes.TunnelPeer{Addr: oldNodeIP},
			nh.endpointEncryptionKey(oldNode))
	}

	// Delete the old ingress IP addresses if they have changed in this node.
	for _, address := range []net.IP{oldNode.IPv4IngressIP, oldNode.IPv6IngressIP} {
		ingressIP := ip.IPToNetPrefix(address)
		if !ingressIP.IsValid() || slices.Contains(ingressIPsAdded, ingressIP) {
			continue
		}

		nh.IPCache.RemoveMetadata(ingressIP, resource,
			labels.LabelIngress,
			ipcacheTypes.TunnelPeer{Addr: oldNodeIP},
			nh.endpointEncryptionKey(oldNode))
	}
}

func (nh *nodeOps) deleted(name string) {
	n, exists := nh.prev[name]
	if !exists {
		return
	}

	log.WithFields(logrus.Fields{
		logfields.ClusterName: n.Cluster,
		logfields.NodeName:    n.Name,
	}).Info("Node deleted")
	if log.Logger.IsLevelEnabled(logrus.DebugLevel) {
		log.Debugf("Received node delete event from %s", n.Source)
	}

	resource := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindNode, "", n.Name)

	delete(nh.prev, n.Name)
	nh.removeNodeFromIPCache(n, resource, nil, nil, nil)
}

func (nh *nodeOps) nodeAddressHasTunnelIP(address nodeTypes.Address) bool {
	// If the host firewall is enabled, all traffic to remote nodes must go
	// through the tunnel to preserve the source identity as part of the
	// encapsulation. In encryption case we also want to use vxlan device
	// to create symmetric traffic when sending nodeIP->pod and pod->nodeIP.
	return address.Type == addressing.NodeCiliumInternalIP || nh.DaemonConfig.NodeEncryptionEnabled() ||
		nh.DaemonConfig.EnableHostFirewall || nh.DaemonConfig.JoinCluster
}

func (nh *nodeOps) nodeAddressHasEncryptKey() bool {
	// If we are doing encryption, but not node based encryption, then do not
	// add a key to the nodeIPs so that we avoid a trip through stack and attempting
	// to encrypt something we know does not have an encryption policy installed
	// in the datapath. By setting key=0 and tunnelIP this will result in traffic
	// being sent unencrypted over overlay device.
	return nh.DaemonConfig.NodeEncryptionEnabled() &&
		// Also ignore any remote node's key if the local node opted to not perform
		// node-to-node encryption
		!node.GetOptOutNodeEncryption()
}

// endpointEncryptionKey returns the encryption key index to use for the health
// and ingress endpoints of a node. This is needed for WireGuard where the
// node's EncryptionKey and the endpoint's EncryptionKey are not the same if
// a node has opted out of node-to-node encryption by zeroing n.EncryptionKey.
// With WireGuard, we always want to encrypt pod-to-pod traffic, thus we return
// a static non-zero encrypt key here.
// With IPSec (or no encryption), the node's encryption key index and the
// encryption key of the endpoint on that node are the same.
func (nh *nodeOps) endpointEncryptionKey(n *nodeTypes.Node) ipcacheTypes.EncryptKey {
	if nh.DaemonConfig.EnableWireguard {
		return ipcacheTypes.EncryptKey(types.StaticEncryptKey)
	}

	return ipcacheTypes.EncryptKey(n.EncryptionKey)
}
