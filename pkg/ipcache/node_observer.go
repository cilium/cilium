// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"go4.org/netipx"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container/set"
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

type nodeObserver struct {
	db          *statedb.DB
	nodes       statedb.Table[*node.Node]
	ipcache     MetadataBatchAPI
	config      *option.DaemonConfig
	clusterInfo cmtypes.ClusterInfo
	underlay    tunnel.UnderlayProtocol
	wgConfig    wgTypes.Config

	lastApplied          map[nodeTypes.Identity]map[cmtypes.PrefixCluster]MU
	optOutNodeEncryption bool
}

// RegisterNodeObserver registers the job that derives IPCache metadata from
// the node table.
func RegisterNodeObserver(
	db *statedb.DB,
	jobs job.Group,
	nodeWriter *node.Writer,
	ipcache MetadataBatchAPI,
	config *option.DaemonConfig,
	clusterInfo cmtypes.ClusterInfo,
	tunnelConfig tunnel.Config,
	wgConfig wgTypes.Config,
) {
	nodeTable := nodeWriter.Table()
	observer := &nodeObserver{
		db:          db,
		nodes:       nodeTable,
		ipcache:     ipcache,
		config:      config,
		clusterInfo: clusterInfo,
		underlay:    tunnelConfig.UnderlayProtocol(),
		wgConfig:    wgConfig,
		lastApplied: map[nodeTypes.Identity]map[cmtypes.PrefixCluster]MU{},
	}
	jobs.Add(job.OneShot("node-ipcache", observer.run))
}

func (o *nodeObserver) run(ctx context.Context, health cell.Health) error {
	if _, err := node.WaitForLocalNodeInit(ctx, o.db, o.nodes); err != nil {
		return nil
	}

	wtxn := o.db.WriteTxn(o.nodes)
	changes, err := o.nodes.Changes(wtxn)
	if err != nil {
		wtxn.Abort()
		return fmt.Errorf("creating node change iterator: %w", err)
	}
	wtxn.Commit()
	defer changes.Close()

	txn := o.db.ReadTxn()
	for {
		seq, watch := changes.Next(txn)
		var batch []statedb.Change[*node.Node]
		for change := range seq {
			batch = append(batch, change)
		}
		o.apply(txn, batch)
		health.OK("Node changes processed")

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
			txn = o.db.ReadTxn()
		}
	}
}

func (o *nodeObserver) apply(
	txn statedb.ReadTxn,
	changes []statedb.Change[*node.Node],
) {
	affected := set.NewSet[nodeTypes.Identity]()
	reapplyNodes := false
	for _, change := range changes {
		affected.Insert(change.Object.Identity())
		if change.Deleted || change.Object.Local == nil {
			continue
		}
		optOut := change.Object.Local.OptOutNodeEncryption
		if o.optOutNodeEncryption != optOut {
			o.optOutNodeEncryption = optOut
			reapplyNodes = true
		}
	}

	if reapplyNodes {
		for n := range o.nodes.All(txn) {
			if n.Local == nil {
				affected.Insert(n.Identity())
			}
		}
	}

	var upserts, removals []MU
	for identity := range affected.Members() {
		old := o.lastApplied[identity]
		n, _, found := o.nodes.Get(txn, node.NodeByName(identity.String()))
		if !found {
			removals = append(removals, metadataValues(old)...)
			delete(o.lastApplied, identity)
			continue
		}

		desired := o.metadataForNode(n)
		if reflect.DeepEqual(old, desired) {
			continue
		}
		upserts = append(upserts, metadataValues(desired)...)
		removals = append(removals, metadataRemovals(old, desired)...)
		o.lastApplied[identity] = desired
	}
	if len(upserts) > 0 {
		o.ipcache.UpsertMetadataBatch(upserts...)
	}
	if len(removals) > 0 {
		o.ipcache.RemoveMetadataBatch(removals...)
	}
}

func (o *nodeObserver) metadataForNode(n *node.Node) map[cmtypes.PrefixCluster]MU {
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
	if value := n.GetNodeIP(o.underlay == tunnel.IPv6); value != nil {
		nodeIP, _ = netipx.FromStdIP(value)
	}
	nodeLabels := o.nodeIdentityLabels(n)
	encryptNodeIPs := o.nodeAddressHasEncryptKey()

	for _, address := range n.IPAddresses {
		prefix := ip.IPToNetPrefix(address.IP)
		prefixCluster := cmtypes.NewLocalPrefixCluster(prefix)
		if address.Type == addressing.NodeCiliumInternalIP {
			prefixCluster = cmtypes.PrefixClusterFrom(prefix)
		}

		var tunnelIP netip.Addr
		if o.nodeAddressHasTunnelIP(address) {
			tunnelIP = nodeIP
		}
		var key uint8
		if encryptNodeIPs {
			key = n.EncryptionKey
		}
		endpointFlags := ipcacheTypes.EndpointFlags{}
		if n.Cluster != o.clusterInfo.Name {
			endpointFlags.SetRemoteCluster(true)
		}
		addressLabels := nodeLabels
		if o.config.PolicyCIDRMatchesNodes() {
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
				o.endpointEncryptionKey(n),
			)
		}
	}

	for _, address := range []netip.Addr{n.IPv4IngressIP.Addr, n.IPv6IngressIP.Addr} {
		prefix := netip.PrefixFrom(address, address.BitLen())
		if prefix.IsValid() {
			add(cmtypes.PrefixClusterFrom(prefix),
				labels.LabelIngress,
				ipcacheTypes.TunnelPeer{Addr: nodeIP},
				o.endpointEncryptionKey(n),
			)
		}
	}
	return metadata
}

func (o *nodeObserver) nodeAddressHasTunnelIP(address nodeTypes.Address) bool {
	return address.Type == addressing.NodeCiliumInternalIP ||
		o.config.NodeEncryptionEnabled() || o.config.EnableHostFirewall
}

func (o *nodeObserver) nodeAddressHasEncryptKey() bool {
	return o.config.NodeEncryptionEnabled() && !o.optOutNodeEncryption
}

func (o *nodeObserver) endpointEncryptionKey(n *node.Node) ipcacheTypes.EncryptKey {
	if o.wgConfig.Enabled() {
		return ipcacheTypes.EncryptKey(wgTypes.StaticEncryptKey)
	}
	return ipcacheTypes.EncryptKey(n.EncryptionKey)
}

func (o *nodeObserver) nodeIdentityLabels(n *node.Node) labels.Labels {
	nodeLabels := labels.NewFrom(labels.LabelRemoteNode)
	if n.Local != nil {
		nodeLabels = labels.NewFrom(labels.LabelHost)
		if o.config.PolicyCIDRMatchesNodes() {
			for _, address := range n.IPAddresses {
				addr, ok := netipx.FromStdIP(address.IP)
				if ok && ((o.config.EnableIPv4 && addr.Is4()) ||
					(o.config.EnableIPv6 && addr.Is6())) {
					nodeLabels.MergeLabels(labels.GetCIDRLabels(
						netip.PrefixFrom(addr, addr.BitLen()),
					))
				}
			}
		}
	}

	if o.config.PerNodeLabelsEnabled() {
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

		newKinds := set.NewSet[reflect.Type]()
		for _, metadata := range newEntry.Metadata {
			newKinds.Insert(reflect.TypeOf(metadata))
		}
		var removed []IPMetadata
		for _, metadata := range oldEntry.Metadata {
			if !newKinds.Has(reflect.TypeOf(metadata)) {
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
