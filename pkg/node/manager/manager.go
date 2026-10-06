// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"golang.org/x/time/rate"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
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

var baseBackgroundSyncInterval = time.Minute

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

var _ Notifier = (*manager)(nil)

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

	// nodeHandlersMu protects the nodeHandlers map against concurrent access.
	nodeHandlersMu lock.RWMutex
	// nodeHandlers has a slice containing all node handlers subscribed to node
	// events.
	nodeHandlers map[node.Handler]struct{}

	// group of jobs, tied to the lifecycle of the manager
	jobGroup job.Group
	// clusterSizeDependantInterval computes background sync intervals from the
	// current size of the node table.
	clusterSizeDependantInterval node.ClusterSizeDependantIntervalFunc

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

	// controllerManager manages the controllers that are launched within the
	// Manager.
	controllerManager *controller.Manager

	// health reports on the current health status of the node manager module.
	health cell.Health

	// Reference to the StateDB
	db *statedb.DB

	// The devices table
	devices statedb.Table[*tables.Device]

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

// Subscribe subscribes the given node handler to node events.
func (m *manager) Subscribe(nh node.Handler) {
	m.nodeHandlersMu.Lock()
	m.nodeHandlers[nh] = struct{}{}
	m.nodeHandlersMu.Unlock()
	// Add all nodes already received by the manager.
	m.mutex.RLock()
	for _, v := range m.nodes {
		v.mutex.Lock()
		if err := nh.NodeAdd(v.node); err != nil {
			m.logger.Error(
				"Failed applying node handler following initial subscribe. Cilium may have degraded functionality. See error message for more details.",
				logfields.Error, err,
				logfields.Handler, nh.Name(),
				logfields.Node, v.node.Name,
			)
		}
		v.mutex.Unlock()
	}
	m.mutex.RUnlock()
}

// Unsubscribe unsubscribes the given node handler with node events.
func (m *manager) Unsubscribe(nh node.Handler) {
	m.nodeHandlersMu.Lock()
	delete(m.nodeHandlers, nh)
	m.nodeHandlersMu.Unlock()
}

// Iter executes the given function in all subscribed node handlers.
func (m *manager) Iter(f func(nh node.Handler)) {
	m.nodeHandlersMu.RLock()
	defer m.nodeHandlersMu.RUnlock()

	for nh := range m.nodeHandlers {
		f(nh)
	}
}

type nodeMetrics struct {
	// metricEventsReceived is the prometheus metric to track the number of
	// node events received
	EventsReceived metric.Vec[metric.Counter]

	// metricNumNodes is the prometheus metric to track the number of nodes
	// being managed
	NumNodes metric.Gauge

	// metricDatapathValidations is the prometheus metric to track the
	// number of datapath node validation calls
	DatapathValidations metric.Counter
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

		DatapathValidations: metric.NewCounter(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_" + "nodes_all_datapath_validations_total",
			Namespace:  metrics.Namespace,
			Subsystem:  "nodes",
			Name:       "all_datapath_validations_total",
			Help:       "Number of validation calls to implement the datapath implementation of a node",
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
	health cell.Health,
	jobGroup job.Group,
	db *statedb.DB,
	devices statedb.Table[*tables.Device],
	wgCfg types.Config,
	writer *node.Writer,
	clusterSizeDependantInterval node.ClusterSizeDependantIntervalFunc,
) (*manager, error) {
	m := &manager{
		logger:                       logger,
		nodes:                        map[nodeTypes.Identity]*nodeEntry{},
		writer:                       writer,
		conf:                         c,
		clusterInfo:                  clusterInfo,
		underlay:                     tunnelConf.UnderlayProtocol(),
		controllerManager:            controller.NewManager(),
		nodeHandlers:                 map[node.Handler]struct{}{},
		ipcache:                      ipCache,
		metrics:                      nodeMetrics,
		health:                       health,
		jobGroup:                     jobGroup,
		clusterSizeDependantInterval: clusterSizeDependantInterval,
		db:                           db,
		devices:                      devices,
		prefixClusterMutatorFn:       func(node *nodeTypes.Node) []cmtypes.PrefixClusterOpts { return nil },
		wgConfig:                     wgCfg,
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

func (m *manager) Start(cell.HookContext) error {
	m.jobGroup.Add(job.OneShot("backgroundSync", m.backgroundSync))

	return nil
}

// Stop shuts down a node manager
func (m *manager) Stop(cell.HookContext) error {
	return nil
}

// backgroundSync ensures that local node has a valid datapath in-place for
// each node in the cluster. See NodeValidateImplementation().
func (m *manager) backgroundSync(ctx context.Context, health cell.Health) error {
	for {
		syncInterval := m.clusterSizeDependantInterval(baseBackgroundSyncInterval)
		startWaiting := time.After(syncInterval)
		m.logger.Debug(
			"Starting new iteration of background sync",
			logfields.SyncInterval, syncInterval,
		)
		err := m.singleBackgroundLoop(ctx, syncInterval)
		m.logger.Debug(
			"Finished iteration of background sync",
			logfields.SyncInterval, syncInterval,
		)

		select {
		case <-ctx.Done():
			return nil
		// This handles cases when we didn't fetch nodes yet (e.g. on bootstrap)
		// but also case when we have 1 node, in which case rate.Limiter doesn't
		// throttle anything.
		case <-startWaiting:
		}

		if err != nil {
			health.Degraded("Failed to apply node validation", err)
		} else {
			health.OK("Node validation successful")
		}
	}
}

func (m *manager) singleBackgroundLoop(ctx context.Context, expectedLoopTime time.Duration) error {
	var errs error
	// get a copy of the node identities to avoid locking the entire manager
	// throughout the process of running the datapath validation.
	nodes := m.GetNodeIdentities()
	limiter := rate.NewLimiter(
		rate.Limit(float64(len(nodes))/float64(expectedLoopTime.Seconds())),
		1, // One token in bucket to amortize for latency of the operation
	)
	for _, nodeIdentity := range nodes {
		if err := limiter.Wait(ctx); err != nil {
			m.logger.Debug(
				"Error while rate limiting backgroundSync updates",
				logfields.Error, err,
			)
		}

		select {
		case <-ctx.Done():
			return nil
		default:
		}
		// Retrieve latest node information in case any event
		// changed the node since the call to GetNodes()
		m.mutex.RLock()
		entry, ok := m.nodes[nodeIdentity]
		if !ok {
			m.mutex.RUnlock()
			continue
		}
		entry.mutex.Lock()
		m.mutex.RUnlock()
		{
			m.Iter(func(nh node.Handler) {
				if err := nh.NodeValidateImplementation(entry.node); err != nil {
					m.logger.Error(
						"Failed to apply node handler during background sync. Cilium may have degraded functionality. See error message for details.",
						logfields.Error, err,
						logfields.Handler, nh.Name(),
						logfields.Node, entry.node.Name,
					)
					errs = errors.Join(errs, fmt.Errorf("failed while handling %s on node %s: %w", nh.Name(), entry.node.Name, err))
				}
			})
		}
		entry.mutex.Unlock()

		m.metrics.DatapathValidations.Inc()
	}
	return errs
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
// the node. If an update or addition has occurred, NodeUpdate() of the datapath
// interface is invoked.
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
// origins from. If the node was removed, NodeDelete() is invoked of the
// datapath interface.
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

// GetNodeIdentities returns a list of all node identities store in node
// manager.
func (m *manager) GetNodeIdentities() []nodeTypes.Identity {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	nodes := make([]nodeTypes.Identity, 0, len(m.nodes))
	for nodeIdentity := range m.nodes {
		nodes = append(nodes, nodeIdentity)
	}

	return nodes
}

// GetNodes returns a copy of all of the nodes as a map from Identity to Node.
func (m *manager) GetNodes() map[nodeTypes.Identity]nodeTypes.Node {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	nodes := make(map[nodeTypes.Identity]nodeTypes.Node, len(m.nodes))
	for nodeIdentity, entry := range m.nodes {
		entry.mutex.Lock()
		nodes[nodeIdentity] = entry.node
		entry.mutex.Unlock()
	}

	return nodes
}

// SetPrefixClusterMutatorFn allows to inject a custom prefix cluster mutator.
// The mutator may then be applied to the PrefixCluster(s) using cmtypes.PrefixClusterFrom.
func (m *manager) SetPrefixClusterMutatorFn(mutator node.PrefixClusterMutatorFn) {
	m.prefixClusterMutatorFn = mutator
	if m.writer != nil {
		m.writer.SetPrefixClusterMutatorFn(mutator)
	}
}
