// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"iter"
	"log/slog"
	"net/netip"
	"slices"
	"sync"

	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	// ClusterNodeTableInitializerName is completed once the initial listing of
	// nodes in the local cluster has been received.
	ClusterNodeTableInitializerName = "node-manager-cluster"
	// MeshNodeTableInitializerName is completed once the initial listing of
	// nodes in remote clusters has been received.
	MeshNodeTableInitializerName = "node-manager-mesh"
)

type nodeEntry struct {
	// mutex serves two purposes:
	// 1. Serialize any direct access to the node field in this entry.
	// 2. Serialize all calls do the datapath layer for a particular node.
	//
	// See description of Manager.mutex for more details
	//
	// If both the nodeEntry.mutex and Manager.mutex must be held, then the
	// Manager.mutex must *always* be acquired first.
	mutex lock.Mutex
	node  nodeTypes.Node
}

// IPCache is the set of interactions the node manager performs with the ipcache
type IPCache interface {
	GetMetadataSourceByPrefix(prefix cmtypes.PrefixCluster) source.Source
	UpsertMetadata(prefix cmtypes.PrefixCluster, src source.Source, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata)
	RemoveMetadata(prefix cmtypes.PrefixCluster, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata)
	UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64)
	RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64)
}

// manager is the entity that manages a collection of nodes
type manager struct {
	logger *slog.Logger
	policy *updatePolicy
	// mutex is the lock protecting access to the nodes map. The mutex must
	// be held for any access of the nodes map.
	//
	// The manager mutex works together with the entry mutex in the
	// following way to minimize the duration the manager mutex is held:
	//
	// 1. Acquire manager mutex to safely access nodes map and to retrieve
	//    node entry.
	// 2. Acquire mutex of the entry while the manager mutex is still held.
	//    This guarantees that no change to the entry has happened.
	// 3. Release of the manager mutex to unblock changes or reads to other
	//    node entries.
	// 4. Change of entry data or performing of datapath interactions
	// 5. Release of the entry mutex
	//
	// If both the nodeEntry.mutex and Manager.mutex must be held, then the
	// Manager.mutex must *always* be acquired first.
	mutex lock.RWMutex

	// nodes is the list of nodes. Access must be protected via mutex.
	nodes map[nodeTypes.Identity]*nodeEntry

	// metrics to track information about the node manager
	metrics *nodeMetrics

	// conf is the configuration of the caller passed in via NewManager.
	// This field is immutable after NewManager()
	conf *option.DaemonConfig
	// clusterInfo is the local cluster information passed in via NewManager.
	// This field is immutable after NewManager()
	clusterInfo cmtypes.ClusterInfo

	underlay tunnel.UnderlayProtocol

	// ipcache is the set operations performed against the ipcache
	ipcache IPCache

	// Reference to the StateDB
	db *statedb.DB

	// writer owns all remote-node table access.
	writer *node.Writer

	// clusterNodeTableInit and meshNodeTableInit mark their respective node
	// sources initialized. The node table is initialized after both complete.
	clusterNodeTableInit func()
	meshNodeTableInit    func()

	// custom mutator function to enrich prefixCluster(s) from node objects.
	prefixClusterMutatorFn node.PrefixClusterMutatorFn

	// wireguard configuration used when calling endpointEncryptionKey.
	wgConfig types.Config
}

type nodeMetrics struct {
	// metricEventsReceived is the prometheus metric to track the number of
	// node events received
	EventsReceived metric.Vec[metric.Counter]

	// metricNumNodes is the prometheus metric to track the number of nodes
	// being managed
	NumNodes metric.Gauge
}

func NewNodeMetrics() *nodeMetrics {
	return &nodeMetrics{
		EventsReceived: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_" + "nodes_all_events_received_total",
			Namespace:  metrics.Namespace,
			Subsystem:  "nodes",
			Name:       "all_events_received_total",
			Help:       "Number of node events received",
		}, []string{"event_type", "source"}),

		NumNodes: metric.NewGauge(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_" + "nodes_all_num",
			Namespace:  metrics.Namespace,
			Subsystem:  "nodes",
			Name:       "all_num",
			Help:       "Number of nodes managed",
		}),
	}
}

// New returns a new node manager
func New(
	logger *slog.Logger,
	c *option.DaemonConfig,
	clusterInfo cmtypes.ClusterInfo,
	tunnelConf tunnel.Config,
	ipCache IPCache,
	nodeMetrics *nodeMetrics,
	db *statedb.DB,
	wgCfg types.Config,
	writer *node.Writer,
) (*manager, error) {
	m := &manager{
		logger:                 logger,
		nodes:                  map[nodeTypes.Identity]*nodeEntry{},
		writer:                 writer,
		conf:                   c,
		clusterInfo:            clusterInfo,
		underlay:               tunnelConf.UnderlayProtocol(),
		ipcache:                ipCache,
		metrics:                nodeMetrics,
		db:                     db,
		prefixClusterMutatorFn: func(node *nodeTypes.Node) []cmtypes.PrefixClusterOpts { return nil },
		wgConfig:               wgCfg,
	}
	m.policy = &updatePolicy{manager: m}
	m.writer.SetUpdatePolicy(m.policy)

	if writer != nil {
		nodeTable := writer.Table()
		wtxn := db.WriteTxn(nodeTable)
		clusterInitDone := m.writer.RegisterInitializer(
			wtxn,
			ClusterNodeTableInitializerName,
		)
		meshInitDone := m.writer.RegisterInitializer(
			wtxn,
			MeshNodeTableInitializerName,
		)
		wtxn.Commit()
		m.clusterNodeTableInit = sync.OnceFunc(func() {
			wtxn := db.WriteTxn(nodeTable)
			clusterInitDone(wtxn)
			wtxn.Commit()
		})
		m.meshNodeTableInit = sync.OnceFunc(func() {
			wtxn := db.WriteTxn(nodeTable)
			meshInitDone(wtxn)
			wtxn.Commit()
		})
	}

	return m, nil
}

func (m *manager) nodeAddressHasTunnelIP(address nodeTypes.Address) bool {
	// If the host firewall is enabled, all traffic to remote nodes must go
	// through the tunnel to preserve the source identity as part of the
	// encapsulation. In encryption case we also want to use vxlan device
	// to create symmetric traffic when sending nodeIP->pod and pod->nodeIP.
	return address.Type == addressing.NodeCiliumInternalIP || m.conf.NodeEncryptionEnabled() ||
		m.conf.EnableHostFirewall
}

func (m *manager) nodeAddressHasEncryptKey() bool {
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
func (m *manager) endpointEncryptionKey(n *nodeTypes.Node) ipcacheTypes.EncryptKey {
	if m.wgConfig.Enabled() {
		return ipcacheTypes.EncryptKey(types.StaticEncryptKey)
	}

	return ipcacheTypes.EncryptKey(n.EncryptionKey)
}

func (m *manager) nodeIdentityLabels(n nodeTypes.Node) labels.Labels {
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

// NodeUpdated is called after the information of a node has been updated. The
// node in the manager is added or updated if the source is allowed to update
// the node.
func (m *manager) NodeUpdated(n nodeTypes.Node) {
	txn := m.db.WriteTxn(m.writer.Table())
	m.writer.Upsert(txn, &n)
	txn.Commit()
}

func (m *manager) cidrsToPrefixesCluster(n *nodeTypes.Node, prefixes ...netip.Prefix) iter.Seq[cmtypes.PrefixCluster] {
	return func(yield func(cmtypes.PrefixCluster) bool) {
		for _, prefix := range prefixes {
			if !yield(cmtypes.PrefixClusterFrom(prefix, m.prefixClusterMutatorFn(n)...)) {
				return
			}
		}
	}
}

func (m *manager) podCIDREntries(source source.Source, resource ipcacheTypes.ResourceID, prefixes iter.Seq[cmtypes.PrefixCluster], tunnelIP netip.Addr, encryptKey uint8) iter.Seq[ipcache.MU] {
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
func (m *manager) removeNodeFromIPCache(oldNode nodeTypes.Node, resource ipcacheTypes.ResourceID,
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
			oldPrefixCluster = cmtypes.PrefixClusterFrom(prefix, m.prefixClusterMutatorFn(&oldNode)...)
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
		for entry := range m.podCIDREntries(oldNode.Source, resource, m.cidrsToPrefixesCluster(&oldNode, oldIPv4PodCIDRs...), oldNodeIP, oldNode.EncryptionKey) {
			if slices.Contains(podCIDRsAdded, entry.Prefix.AsPrefix()) {
				continue
			}
			mu = append(mu, entry)
		}
		for entry := range m.podCIDREntries(oldNode.Source, resource, m.cidrsToPrefixesCluster(&oldNode, oldIPv6PodCIDRs...), oldNodeIP, oldNode.EncryptionKey) {
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

		prefixCluster := cmtypes.PrefixClusterFrom(prefix, m.prefixClusterMutatorFn(&oldNode)...)

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

		prefixCluster := cmtypes.PrefixClusterFrom(prefix, m.prefixClusterMutatorFn(&oldNode)...)

		m.ipcache.RemoveMetadata(prefixCluster, resource,
			labels.LabelIngress,
			ipcacheTypes.AllMetadata{})
	}
}

// NodeDeleted is called after a node has been deleted. It removes the node
// from the manager if the node is still owned by the source of which the event
// originates.
func (m *manager) NodeDeleted(n nodeTypes.Node) {
	txn := m.db.WriteTxn(m.writer.Table())
	m.writer.Delete(txn, n.Source, n.Identity())
	txn.Commit()
}

// NodeSync signals that the initial local-cluster node listing is complete.
func (m *manager) NodeSync() {
	if m.clusterNodeTableInit != nil {
		m.clusterNodeTableInit()
	}
}

// MeshNodeSync signals that the initial clustermesh node listing is complete.
func (m *manager) MeshNodeSync() {
	if m.meshNodeTableInit != nil {
		m.meshNodeTableInit()
	}
}

// SetPrefixClusterMutatorFn allows to inject a custom prefix cluster mutator.
// The mutator may then be applied to the PrefixCluster(s) using cmtypes.PrefixClusterFrom.
func (m *manager) SetPrefixClusterMutatorFn(mutator node.PrefixClusterMutatorFn) {
	m.prefixClusterMutatorFn = mutator
	if m.writer != nil {
		m.writer.SetPrefixClusterMutatorFn(mutator)
	}
}
