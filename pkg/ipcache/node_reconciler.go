// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"reflect"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"go4.org/netipx"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ip"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const nodeReconcilerName = "node-ipcache"

// NodeReconcilerCell derives IPCache metadata from the node table.
var NodeReconcilerCell = cell.Module(
	"node-ipcache",
	"Derives IPCache metadata from Cilium nodes",
	cell.Invoke(registerNodeReconciler),
)

type nodeReconcilerOps struct {
	db          *statedb.DB
	nodes       statedb.RWTable[*node.Node]
	ipcache     MetadataBatchAPI
	config      *option.DaemonConfig
	clusterInfo cmtypes.ClusterInfo
	underlay    tunnel.UnderlayProtocol
	wgConfig    wgTypes.Config

	lastApplied map[nodeTypes.Identity]map[cmtypes.PrefixCluster]MU
	localOptOut *bool
}

var _ reconciler.Operations[*node.Node] = (*nodeReconcilerOps)(nil)

func registerNodeReconciler(
	params reconciler.Params,
	nodes statedb.Table[*node.Node],
	ipcache MetadataBatchAPI,
	config *option.DaemonConfig,
	clusterInfo cmtypes.ClusterInfo,
	tunnelConfig tunnel.Config,
	wgConfig wgTypes.Config,
) error {
	nodeTable := nodes.(statedb.RWTable[*node.Node])
	_, err := reconciler.Register(
		params,
		nodeTable,
		(*node.Node).DeepCopy,
		func(n *node.Node, status reconciler.Status) *node.Node {
			n.Statuses = n.Statuses.Set(nodeReconcilerName, status)
			return n
		},
		func(n *node.Node) reconciler.Status {
			return n.Statuses.Get(nodeReconcilerName)
		},
		&nodeReconcilerOps{
			db:          params.DB,
			nodes:       nodeTable,
			ipcache:     ipcache,
			config:      config,
			clusterInfo: clusterInfo,
			underlay:    tunnelConfig.UnderlayProtocol(),
			wgConfig:    wgConfig,
			lastApplied: map[nodeTypes.Identity]map[cmtypes.PrefixCluster]MU{},
		},
		nil,
		reconciler.WithName(nodeReconcilerName),
		reconciler.WithoutPruning(),
	)
	if err != nil {
		return fmt.Errorf("registering node IPCache reconciler: %w", err)
	}
	return nil
}

func (ops *nodeReconcilerOps) Update(
	_ context.Context,
	txn statedb.ReadTxn,
	_ statedb.Revision,
	n *node.Node,
) error {
	desired := ops.metadataForNode(txn, n)
	if len(desired) > 0 {
		ops.ipcache.UpsertMetadataBatch(metadataValues(desired)...)
	}

	old := ops.lastApplied[n.Identity()]
	if removals := metadataRemovals(old, desired); len(removals) > 0 {
		ops.ipcache.RemoveMetadataBatch(removals...)
	}
	ops.lastApplied[n.Identity()] = desired

	if n.Local != nil {
		optOut := n.Local.OptOutNodeEncryption
		changed := ops.localOptOut != nil && *ops.localOptOut != optOut
		ops.localOptOut = &optOut
		if changed {
			return ops.invalidateRemoteNodes()
		}
	}
	return nil
}

func (ops *nodeReconcilerOps) Delete(
	_ context.Context,
	txn statedb.ReadTxn,
	_ statedb.Revision,
	n *node.Node,
) error {
	metadata, found := ops.lastApplied[n.Identity()]
	if !found {
		metadata = ops.metadataForNode(txn, n)
	}
	if len(metadata) > 0 {
		ops.ipcache.RemoveMetadataBatch(metadataValues(metadata)...)
	}
	delete(ops.lastApplied, n.Identity())
	if n.Local != nil {
		oldOptOut := n.Local.OptOutNodeEncryption
		ops.localOptOut = nil
		newOptOut := false
		if local, _, found := ops.nodes.Get(txn, node.LocalNodeQuery); found {
			newOptOut = local.Local.OptOutNodeEncryption
			ops.localOptOut = &newOptOut
		}
		if oldOptOut != newOptOut {
			return ops.invalidateRemoteNodes()
		}
	}
	return nil
}

func (*nodeReconcilerOps) Prune(
	context.Context,
	statedb.ReadTxn,
	iter.Seq2[*node.Node, statedb.Revision],
) error {
	// IPCache metadata is reconstructed from the node table on every start.
	return nil
}

func (ops *nodeReconcilerOps) invalidateRemoteNodes() error {
	txn := ops.db.WriteTxn(ops.nodes)
	defer txn.Abort()
	for n := range ops.nodes.All(txn) {
		if n.Local != nil {
			continue
		}
		status := n.Statuses.Get(nodeReconcilerName)
		if status.IsPendingOrRefreshing() {
			continue
		}
		n = n.DeepCopy()
		n.Statuses = n.Statuses.Set(nodeReconcilerName, reconciler.StatusPending())
		if _, _, err := ops.nodes.Insert(txn, n); err != nil {
			return fmt.Errorf("marking node %s for IPCache reconciliation: %w", n.Fullname(), err)
		}
	}
	txn.Commit()
	return nil
}

func (ops *nodeReconcilerOps) metadataForNode(
	txn statedb.ReadTxn,
	n *node.Node,
) map[cmtypes.PrefixCluster]MU {
	metadata := map[cmtypes.PrefixCluster]MU{}
	resource := ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindNode,
		n.Cluster,
		n.Name,
	)
	add := func(prefix cmtypes.PrefixCluster, values ...IPMetadata) {
		entry := metadata[prefix]
		entry.Prefix = prefix
		entry.Source = n.Source
		entry.Resource = resource
		entry.Metadata = append(entry.Metadata, values...)
		metadata[prefix] = entry
	}

	var nodeIP netip.Addr
	if value := n.GetNodeIP(ops.underlay == tunnel.IPv6); value != nil {
		nodeIP, _ = netipx.FromStdIP(value)
	}
	nodeLabels := ops.nodeIdentityLabels(n)
	encryptNodeIPs := ops.nodeAddressHasEncryptKey(txn)

	for _, address := range n.IPAddresses {
		prefix := ip.IPToNetPrefix(address.IP)
		prefixCluster := cmtypes.NewLocalPrefixCluster(prefix)
		if address.Type == addressing.NodeCiliumInternalIP {
			prefixCluster = cmtypes.PrefixClusterFrom(prefix)
		}

		var tunnelIP netip.Addr
		if ops.nodeAddressHasTunnelIP(address) {
			tunnelIP = nodeIP
		}
		var key uint8
		if encryptNodeIPs {
			key = n.EncryptionKey
		}
		endpointFlags := ipcacheTypes.EndpointFlags{}
		if n.Cluster != ops.clusterInfo.Name {
			endpointFlags.SetRemoteCluster(true)
		}
		addressLabels := nodeLabels
		if ops.config.PolicyCIDRMatchesNodes() {
			addressLabels = labels.NewFrom(nodeLabels)
			addressLabels.MergeLabels(labels.GetCIDRLabels(prefix))
		}
		add(prefixCluster,
			addressLabels,
			ipcacheTypes.TunnelPeer{Addr: tunnelIP},
			ipcacheTypes.EncryptKey(key),
			endpointFlags,
		)
	}

	if n.Local == nil {
		for _, prefixes := range [][]netip.Prefix{
			n.GetIPv4AllocCIDRs(),
			n.GetIPv6AllocCIDRs(),
		} {
			for _, prefix := range prefixes {
				if !prefix.IsValid() {
					continue
				}
				prefixCluster := cmtypes.PrefixClusterFrom(prefix)
				add(prefixCluster,
					worldLabelForPrefix(prefix),
					ipcacheTypes.TunnelPeer{Addr: nodeIP},
					ipcacheTypes.EncryptKey(n.EncryptionKey),
				)
			}
		}
	}

	for _, address := range []netip.Addr{n.IPv4HealthIP.Addr, n.IPv6HealthIP.Addr} {
		prefix := netip.PrefixFrom(address, address.BitLen())
		if prefix.IsValid() {
			add(cmtypes.PrefixClusterFrom(prefix),
				labels.LabelHealth,
				ipcacheTypes.TunnelPeer{Addr: nodeIP},
				ops.endpointEncryptionKey(n),
			)
		}
	}

	for _, address := range []net.IP{n.IPv4IngressIP, n.IPv6IngressIP} {
		prefix := ip.IPToNetPrefix(address)
		if prefix.IsValid() {
			add(cmtypes.PrefixClusterFrom(prefix),
				labels.LabelIngress,
				ipcacheTypes.TunnelPeer{Addr: nodeIP},
				ops.endpointEncryptionKey(n),
			)
		}
	}
	return metadata
}

func (ops *nodeReconcilerOps) nodeAddressHasTunnelIP(address nodeTypes.Address) bool {
	return address.Type == addressing.NodeCiliumInternalIP ||
		ops.config.NodeEncryptionEnabled() || ops.config.EnableHostFirewall
}

func (ops *nodeReconcilerOps) nodeAddressHasEncryptKey(txn statedb.ReadTxn) bool {
	optOut := false
	if local, _, found := ops.nodes.Get(txn, node.LocalNodeQuery); found {
		optOut = local.Local.OptOutNodeEncryption
	}
	return ops.config.NodeEncryptionEnabled() && !optOut
}

func (ops *nodeReconcilerOps) endpointEncryptionKey(n *node.Node) ipcacheTypes.EncryptKey {
	if ops.wgConfig.Enabled() {
		return ipcacheTypes.EncryptKey(wgTypes.StaticEncryptKey)
	}
	return ipcacheTypes.EncryptKey(n.EncryptionKey)
}

func (ops *nodeReconcilerOps) nodeIdentityLabels(n *node.Node) labels.Labels {
	nodeLabels := labels.NewFrom(labels.LabelRemoteNode)
	if n.Local != nil {
		nodeLabels = labels.NewFrom(labels.LabelHost)
		if ops.config.PolicyCIDRMatchesNodes() {
			for _, address := range n.IPAddresses {
				addr, ok := netipx.FromStdIP(address.IP)
				if ok && ((ops.config.EnableIPv4 && addr.Is4()) ||
					(ops.config.EnableIPv6 && addr.Is6())) {
					nodeLabels.MergeLabels(labels.GetCIDRLabels(
						netip.PrefixFrom(addr, addr.BitLen()),
					))
				}
			}
		}
	}

	if ops.config.PerNodeLabelsEnabled() {
		filtered, _ := labelsfilter.FilterNodeLabels(
			labels.Map2Labels(n.Labels, labels.LabelSourceNode),
		)
		nodeLabels.MergeLabels(filtered)
		nodeLabels.MergeLabels(labels.Map2Labels(map[string]string{
			k8sConst.PolicyLabelCluster: n.Cluster,
		}, labels.LabelSourceK8s))
	}
	return nodeLabels
}

func worldLabelForPrefix(prefix netip.Prefix) labels.Labels {
	lbls := make(labels.Labels, 1)
	lbls.AddWorldLabel(prefix.Addr())
	return lbls
}

func metadataValues(entries map[cmtypes.PrefixCluster]MU) []MU {
	values := make([]MU, 0, len(entries))
	for _, entry := range entries {
		values = append(values, entry)
	}
	return values
}

func metadataRemovals(
	old, desired map[cmtypes.PrefixCluster]MU,
) []MU {
	removals := make([]MU, 0, len(old))
	for prefix, oldEntry := range old {
		newEntry, found := desired[prefix]
		if !found {
			removals = append(removals, oldEntry)
			continue
		}

		newKinds := map[reflect.Type]struct{}{}
		for _, metadata := range newEntry.Metadata {
			newKinds[reflect.TypeOf(metadata)] = struct{}{}
		}
		var removed []IPMetadata
		for _, metadata := range oldEntry.Metadata {
			if _, found := newKinds[reflect.TypeOf(metadata)]; !found {
				removed = append(removed, metadata)
			}
		}
		if len(removed) > 0 {
			oldEntry.Metadata = removed
			removals = append(removals, oldEntry)
		}
	}
	return removals
}
