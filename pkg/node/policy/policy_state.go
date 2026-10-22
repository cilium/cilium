// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"iter"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/wireguard/types"
)

type nodeEntry struct {
	// mutex serves two purposes:
	// 1. Serialize any direct access to the node field in this entry.
	// 2. Serialize all calls do the datapath layer for a particular node.
	//
	// See description of updatePolicy.mutex for more details.
	//
	// If both the nodeEntry.mutex and updatePolicy.mutex must be held, then the
	// updatePolicy.mutex must *always* be acquired first.
	mutex lock.Mutex
	node  nodeTypes.Node
}

// IPCache is the set of interactions the update policy performs with the ipcache.
type IPCache interface {
	GetMetadataSourceByPrefix(prefix cmtypes.PrefixCluster) source.Source
	UpsertMetadata(prefix cmtypes.PrefixCluster, src source.Source, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata)
	RemoveMetadata(prefix cmtypes.PrefixCluster, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata)
	UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64)
	RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64)
}

// updatePolicy manages the accepted-node cache and its IPCache metadata.
type updatePolicy struct {
	logger *slog.Logger
	// mutex is the lock protecting access to the nodes map. The mutex must
	// be held for any access of the nodes map.
	//
	// The policy mutex works together with the entry mutex in the
	// following way to minimize the duration the policy mutex is held:
	//
	// 1. Acquire policy mutex to safely access nodes map and to retrieve
	//    node entry.
	// 2. Acquire mutex of the entry while the policy mutex is still held.
	//    This guarantees that no change to the entry has happened.
	// 3. Release of the policy mutex to unblock changes or reads to other
	//    node entries.
	// 4. Change of entry data or performing of datapath interactions
	// 5. Release of the entry mutex
	//
	// If both the nodeEntry.mutex and updatePolicy.mutex must be held, then the
	// updatePolicy.mutex must *always* be acquired first.
	mutex lock.RWMutex

	// nodes is the list of nodes. Access must be protected via mutex.
	nodes map[nodeTypes.Identity]*nodeEntry

	// conf is immutable after policy construction.
	conf *option.DaemonConfig
	// clusterInfo is immutable after policy construction.
	clusterInfo cmtypes.ClusterInfo

	underlay tunnel.UnderlayProtocol

	// ipcache is the set operations performed against the ipcache
	ipcache IPCache

	// Reference to the StateDB
	db *statedb.DB

	// writer owns all remote-node table access.
	writer *node.Writer

	// wireguard configuration used when calling endpointEncryptionKey.
	wgConfig types.Config
}

// newUpdatePolicy constructs the policy and installs it on the writer.
func newUpdatePolicy(
	logger *slog.Logger,
	c *option.DaemonConfig,
	clusterInfo cmtypes.ClusterInfo,
	tunnelConf tunnel.Config,
	ipCache IPCache,
	db *statedb.DB,
	wgCfg types.Config,
	writer *node.Writer,
) (*updatePolicy, error) {
	m := &updatePolicy{
		logger:      logger,
		nodes:       map[nodeTypes.Identity]*nodeEntry{},
		writer:      writer,
		conf:        c,
		clusterInfo: clusterInfo,
		underlay:    tunnelConf.UnderlayProtocol(),
		ipcache:     ipCache,
		db:          db,
		wgConfig:    wgCfg,
	}
	if writer != nil {
		writer.SetUpdatePolicy(m)
	}

	return m, nil
}

func (m *updatePolicy) nodeAddressHasTunnelIP(address nodeTypes.Address) bool {
	// If the host firewall is enabled, all traffic to remote nodes must go
	// through the tunnel to preserve the source identity as part of the
	// encapsulation. In encryption case we also want to use vxlan device
	// to create symmetric traffic when sending nodeIP->pod and pod->nodeIP.
	return address.Type == addressing.NodeCiliumInternalIP || m.conf.NodeEncryptionEnabled() ||
		m.conf.EnableHostFirewall
}

func (m *updatePolicy) nodeAddressHasEncryptKey() bool {
	optOut := false
	if m.writer != nil && m.db != nil {
		if localNode, _, found := m.writer.Table().Get(m.db.ReadTxn(), node.LocalNodeQuery); found {
			optOut = localNode.Local.OptOutNodeEncryption
		}
	}

	// If we are doing encryption, but not node based encryption, then do not
	// add a key to the nodeIPs so that we avoid a trip through stack and attempting
	// to encrypt something we know does not have an encryption policy installed
	// in the datapath. By setting key=0 and tunnelIP this will result in traffic
	// being sent unencrypted over overlay device.
	return m.conf.NodeEncryptionEnabled() &&
		// Also ignore any remote node's key if the local node opted to not perform
		// node-to-node encryption
		!optOut
}

// endpointEncryptionKey returns the encryption key index to use for the health
// and ingress endpoints of a node. This is needed for WireGuard where the
// node's EncryptionKey and the endpoint's EncryptionKey are not the same if
// a node has opted out of node-to-node encryption by zeroing n.EncryptionKey.
// With WireGuard, we always want to encrypt pod-to-pod traffic, thus we return
// a static non-zero encrypt key here.
// With IPSec (or no encryption), the node's encryption key index and the
// encryption key of the endpoint on that node are the same.
func (m *updatePolicy) endpointEncryptionKey(n *nodeTypes.Node) ipcacheTypes.EncryptKey {
	if m.wgConfig.Enabled() {
		return ipcacheTypes.EncryptKey(types.StaticEncryptKey)
	}

	return ipcacheTypes.EncryptKey(n.EncryptionKey)
}

func (m *updatePolicy) nodeIdentityLabels(n nodeTypes.Node) labels.Labels {
	nodeLabels := labels.NewFrom(labels.LabelRemoteNode)
	if n.IsLocal() {
		nodeLabels = labels.NewFrom(labels.LabelHost)
	}

	// if per-node labels are enabled, then copy labels from the Node
	// object to the node's identity.
	if option.Config.PerNodeLabelsEnabled() {
		lbls := labels.Map2Labels(n.Labels, labels.LabelSourceNode)
		filteredLbls, _ := labelsfilter.FilterNodeLabels(lbls)
		nodeLabels.MergeLabels(filteredLbls)
		nodeLabels.MergeLabels(labels.Map2Labels(map[string]string{
			k8sConst.PolicyLabelCluster: n.Cluster,
		}, labels.LabelSourceK8s))
	}

	return nodeLabels
}

// worldLabelForPrefix returns the labels which will resolve to
// reserved:world identity given the provided prefix and the
// current cluster configuration in terms of dual-stack.
func worldLabelForPrefix(prefix netip.Prefix) labels.Labels {
	lbls := make(labels.Labels, 1)
	lbls.AddWorldLabel(prefix.Addr())
	return lbls
}

func (m *updatePolicy) cidrsToPrefixesCluster(mutator node.PrefixClusterMutatorFn, n *nodeTypes.Node, prefixes ...netip.Prefix) iter.Seq[cmtypes.PrefixCluster] {
	return func(yield func(cmtypes.PrefixCluster) bool) {
		for _, prefix := range prefixes {
			if !yield(cmtypes.PrefixClusterFrom(prefix, prefixClusterOpts(mutator, n)...)) {
				return
			}
		}
	}
}

func (m *updatePolicy) podCIDREntries(source source.Source, resource ipcacheTypes.ResourceID, prefixes iter.Seq[cmtypes.PrefixCluster], tunnelIP netip.Addr, encryptKey uint8) iter.Seq[ipcache.MU] {
	return func(yield func(ipcache.MU) bool) {
		for prefix := range prefixes {
			if !prefix.IsValid() {
				continue
			}

			metadata := []ipcache.IPMetadata{
				worldLabelForPrefix(prefix.AsPrefix()),
				ipcacheTypes.TunnelPeer{Addr: tunnelIP},
				ipcacheTypes.EncryptKey(encryptKey),
			}

			if !yield(ipcache.MU{
				Prefix:   prefix,
				Source:   source,
				Resource: resource,
				Metadata: metadata,
			}) {
				return
			}
		}
	}
}

// removeNodeFromIPCache removes all addresses associated with oldNode from the IPCache,
// unless they are present in the nodeIPsAdded, healthIPsAdded, ingressIPsAdded lists.
// Removes all pod CIDRs associated with the oldNode from IPCache, unless they are present
// in podCIDRsAdded.
// The removal logic in this function should mirror the upsert logic in nodeAddressHasTunnelIP.
func (m *updatePolicy) removeNodeFromIPCache(mutator node.PrefixClusterMutatorFn, oldNode nodeTypes.Node, resource ipcacheTypes.ResourceID,
	nodeIPsAdded, healthIPsAdded, ingressIPsAdded, podCIDRsAdded []netip.Prefix,
) {
	var oldNodeIP netip.Addr
	if nIP := oldNode.GetNodeIP(false); nIP.IsValid() {
		oldNodeIP = nIP
	}

	// Delete the old node IP addresses if they have changed in this node.
	for _, address := range oldNode.IPAddresses {
		prefix := netip.PrefixFrom(address.IP.Addr, address.IP.BitLen())
		if slices.Contains(nodeIPsAdded, prefix) {
			continue
		}

		var oldPrefixCluster cmtypes.PrefixCluster
		if address.Type == addressing.NodeCiliumInternalIP {
			oldPrefixCluster = cmtypes.PrefixClusterFrom(prefix, prefixClusterOpts(mutator, &oldNode)...)
		} else {
			oldPrefixCluster = cmtypes.NewLocalPrefixCluster(prefix)
		}

		m.ipcache.RemoveMetadata(oldPrefixCluster, resource, ipcacheTypes.AllMetadata{})

	}

	// Remove old pod CIDR fallback entries from IPCache
	if !oldNode.IsLocal() {
		oldIPv4PodCIDRs := oldNode.GetIPv4AllocCIDRs()
		oldIPv6PodCIDRs := oldNode.GetIPv6AllocCIDRs()

		mu := make([]ipcache.MU, 0, len(oldIPv4PodCIDRs)+len(oldIPv6PodCIDRs))
		for entry := range m.podCIDREntries(oldNode.Source, resource, m.cidrsToPrefixesCluster(mutator, &oldNode, oldIPv4PodCIDRs...), oldNodeIP, oldNode.EncryptionKey) {
			if slices.Contains(podCIDRsAdded, entry.Prefix.AsPrefix()) {
				continue
			}
			mu = append(mu, entry)
		}
		for entry := range m.podCIDREntries(oldNode.Source, resource, m.cidrsToPrefixesCluster(mutator, &oldNode, oldIPv6PodCIDRs...), oldNodeIP, oldNode.EncryptionKey) {
			if slices.Contains(podCIDRsAdded, entry.Prefix.AsPrefix()) {
				continue
			}
			mu = append(mu, entry)
		}
		m.ipcache.RemoveMetadataBatch(mu...)
	}

	// Delete the old health IP addresses if they have changed in this node.
	for _, address := range []netip.Addr{oldNode.IPv4HealthIP.Addr, oldNode.IPv6HealthIP.Addr} {
		prefix := netip.PrefixFrom(address, address.BitLen())
		if !prefix.IsValid() || slices.Contains(healthIPsAdded, prefix) {
			continue
		}

		prefixCluster := cmtypes.PrefixClusterFrom(prefix, prefixClusterOpts(mutator, &oldNode)...)

		m.ipcache.RemoveMetadata(prefixCluster, resource,
			labels.LabelHealth,
			ipcacheTypes.AllMetadata{})
	}

	// Delete the old ingress IP addresses if they have changed in this node.
	for _, address := range []netip.Addr{oldNode.IPv4IngressIP.Addr, oldNode.IPv6IngressIP.Addr} {
		prefix := netip.PrefixFrom(address, address.BitLen())
		if !prefix.IsValid() || slices.Contains(ingressIPsAdded, prefix) {
			continue
		}

		prefixCluster := cmtypes.PrefixClusterFrom(prefix, prefixClusterOpts(mutator, &oldNode)...)

		m.ipcache.RemoveMetadata(prefixCluster, resource,
			labels.LabelIngress,
			ipcacheTypes.AllMetadata{})
	}
}
