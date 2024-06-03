// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

var (
	baseBackgroundSyncInterval = time.Minute
	defaultNodeUpdateInterval  = 10 * time.Second
)

// IPSetFilterFn is a function allowing to optionally filter out the insertion
// of IPSet entries based on node characteristics. The insertion is performed
// if the function returns false, and skipped otherwise.
type IPSetFilterFn func(*nodeTypes.Node) bool

var _ Notifier = (*manager)(nil)

// manager is the entity that manages a collection of nodes
type manager struct {
	db         *statedb.DB
	nodesTable statedb.RWTable[node.Node]

	addHandler chan datapath.NodeHandler
	delHandler chan datapath.NodeHandler

	// metrics to track information about the node manager
	metrics *nodeMetrics

	// conf is the configuration of the caller passed in via NewManager.
	// This field is immutable after NewManager()
	conf *option.DaemonConfig

	// ipsetMgr is the ipset cluster nodes configuration manager
	ipsetMgr         ipset.Manager
	ipsetInitializer ipset.Initializer
	ipsetFilter      IPSetFilterFn

	jobGroup job.Group

	nodeNeighbors datapath.NodeNeighbors

	markTableInitialized func(statedb.WriteTxn)
}

// Subscribe subscribes the given node handler to node events.
func (m *manager) Subscribe(nh datapath.NodeHandler) {
	m.addHandler <- nh
}

// Unsubscribe unsubscribes the given node handler with node events.
func (m *manager) Unsubscribe(nh datapath.NodeHandler) {
	m.delHandler <- nh
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

// ProcessNodeDeletion upon node deletion ensures metrics associated
// with the deleted node are no longer reported.
// Notably for metrics node connectivity status and latency metrics
func (*nodeMetrics) ProcessNodeDeletion(clusterName, nodeName string) {
	// Removes all connectivity status associated with the deleted node.
	_ = metrics.NodeConnectivityStatus.DeletePartialMatch(prometheus.Labels{
		metrics.LabelSourceCluster:  clusterName,
		metrics.LabelSourceNodeName: nodeName,
	})
	_ = metrics.NodeConnectivityStatus.DeletePartialMatch(prometheus.Labels{
		metrics.LabelTargetCluster:  clusterName,
		metrics.LabelTargetNodeName: nodeName,
	})

	// Removes all connectivity latency associated with the deleted node.
	_ = metrics.NodeConnectivityLatency.DeletePartialMatch(prometheus.Labels{
		metrics.LabelSourceCluster:  clusterName,
		metrics.LabelSourceNodeName: nodeName,
	})
	_ = metrics.NodeConnectivityLatency.DeletePartialMatch(prometheus.Labels{
		metrics.LabelTargetCluster:  clusterName,
		metrics.LabelTargetNodeName: nodeName,
	})
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
func New(p NodeManagerParams) (*manager, error) {
	if p.IPSetFilter == nil {
		p.IPSetFilter = func(*nodeTypes.Node) bool { return false }
	}

	txn := p.DB.WriteTxn(p.NodesTable)
	init := p.NodesTable.RegisterInitializer(txn)
	txn.Commit()

	m := &manager{
		db:                   p.DB,
		nodesTable:           p.NodesTable,
		markTableInitialized: init,
		addHandler:           make(chan datapath.NodeHandler),
		delHandler:           make(chan datapath.NodeHandler),
		conf:                 p.DaemonConfig,
		ipsetMgr:             p.IPSetMgr,
		ipsetInitializer:     p.IPSetMgr.NewInitializer(),
		ipsetFilter:          p.IPSetFilter,
		metrics:              p.NodeMetrics,
		nodeNeighbors:        p.NodeNeighbors,
		jobGroup:             p.Jobs.NewGroup(p.Health),
	}

	m.jobGroup.Add(job.OneShot(
		"node-handlers",
		m.nodeHandlerLoop))
	m.jobGroup.Add(job.OneShot(
		"neighbor-refresh",
		m.neighRefreshLoop))

	return m, nil
}

func (m *manager) Start(ctx cell.HookContext) error {
	return m.jobGroup.Start(ctx)
}

// Stop shuts down a node manager
func (m *manager) Stop(ctx cell.HookContext) error {
	return m.jobGroup.Stop(ctx)
}

// ClusterSizeDependantInterval returns a time.Duration that is dependant on
// the cluster size, i.e. the number of nodes that have been discovered. This
// can be used to control sync intervals of shared or centralized resources to
// avoid overloading these resources as the cluster grows.
//
// Example sync interval with baseInterval = 1 * time.Minute
//
// nodes | sync interval
// ------+-----------------
// 1     |   41.588830833s
// 2     | 1m05.916737320s
// 4     | 1m36.566274746s
// 8     | 2m11.833474640s
// 16    | 2m49.992800643s
// 32    | 3m29.790453687s
// 64    | 4m10.463236193s
// 128   | 4m51.588744261s
// 256   | 5m32.944565093s
// 512   | 6m14.416550710s
// 1024  | 6m55.946873494s
// 2048  | 7m37.506428894s
// 4096  | 8m19.080616652s
// 8192  | 9m00.662124608s
// 16384 | 9m42.247293667s
func (m *manager) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	numNodes := m.nodesTable.NumObjects(m.db.ReadTxn())
	return backoff.ClusterSizeDependantInterval(baseInterval, numNodes)
}

func (m *manager) backgroundSyncInterval() time.Duration {
	return m.ClusterSizeDependantInterval(baseBackgroundSyncInterval)
}

func (m *manager) nodeHandlerLoop(ctx context.Context, health cell.Health) error {
	wtxn := m.db.WriteTxn(m.nodesTable)
	changes, err := m.nodesTable.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}
	defer changes.Close()
	changesWatch := make(chan struct{})
	close(changesWatch)

	currentNodes := map[nodeTypes.Identity]node.Node{}
	handlers := sets.New[datapath.NodeHandler]()

	syncTimer, syncTimerDone := inctimer.New()
	defer syncTimerDone()
	syncInterval := m.backgroundSyncInterval()
	syncWatch := syncTimer.After(syncInterval)

	syncHealth := health.NewScope("validate")
	defer syncHealth.Close()
	numEvents := 0

	handlerHealth := health.NewScope("handlers")
	defer handlerHealth.Close()

	limiter := rate.NewLimiter(10*time.Millisecond, 1)
	defer limiter.Stop()

	for {
		for change, _, ok := changes.Next(); ok; change, _, ok = changes.Next() {
			numEvents++
			node := change.Object
			identity := node.Identity()
			oldNode, oldNodeExists := currentNodes[identity]
			var emit func(h datapath.NodeHandler) error
			switch {
			case change.Deleted:
				delete(currentNodes, identity)
				emit = func(h datapath.NodeHandler) error {
					return h.NodeDelete(node.GetNode())
				}
				m.metrics.NumNodes.Dec()
				m.metrics.ProcessNodeDeletion(node.Cluster(), node.Name())

			case oldNodeExists:
				currentNodes[identity] = node
				emit = func(h datapath.NodeHandler) error {
					return h.NodeUpdate(oldNode.GetNode(), node.GetNode())
				}
			default:
				m.metrics.NumNodes.Inc()
				currentNodes[identity] = node
				emit = func(h datapath.NodeHandler) error {
					return h.NodeAdd(node.GetNode())
				}
			}
			var lastError error
			for h := range handlers {
				err := emit(h)
				if err != nil {
					log.WithFields(logrus.Fields{
						"handler": h.Name(),
						"node":    node.Name,
					}).WithError(err).
						Error("Failed to handle node event while applying handler. Cilium may be have degraded functionality.")

					lastError = err
				}
			}
			if lastError != nil {
				handlerHealth.Degraded("Failure handling node event", lastError)
			} else {
				handlerHealth.OK(fmt.Sprintf("%d nodes, %d events processed", len(currentNodes), numEvents))
			}
		}

		if err := limiter.Wait(ctx); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return nil

		case <-changes.Watch(m.db.ReadTxn()):

		case h := <-m.addHandler:
			handlers.Insert(h)
			for _, node := range currentNodes {
				if err := h.NodeAdd(node.GetNode()); err != nil {
					log.WithFields(logrus.Fields{
						"handler": h.Name(),
						"node":    node.Name,
					}).WithError(err).Error("Failed applying node handler following initial subscribe. Cilium may have degraded functionality.")
				}
			}
		case h := <-m.delHandler:
			handlers.Delete(h)

		case <-syncWatch:
			syncInterval = m.backgroundSyncInterval()
			log.WithField("syncInterval", syncInterval.String()).Debug("Performing regular background work")
			syncWatch = syncTimer.After(syncInterval)
			var errs []error
			for _, node := range currentNodes {
				for h := range handlers {
					if err := h.NodeValidateImplementation(node.GetNode()); err != nil {
						log.WithFields(logrus.Fields{
							"handler": h.Name(),
							"node":    node.Name,
						}).WithError(err).
							Error("Failed to apply node handler during background sync. Cilium may have degraded functionality.")
						errs = append(errs, fmt.Errorf("%s: node %s: %w", h.Name(), node.Name(), err))
					}
				}
				m.metrics.DatapathValidations.Inc()
			}
			if errs != nil {
				syncHealth.Degraded("Failed to apply node validation", errors.Join(errs...))
			} else {
				syncHealth.OK("Node validation successful")
			}
		}
	}
}

// neighRefreshLoop does periodic neighbor table refresh for non-local nodes.
// Every [ARPPingRefreshPeriod] it will queue refreshes for the neighbors, spread over
// a random time interval. On failure to refresh the health with scope 'neighbors'
// is marked degraded.
func (m *manager) neighRefreshLoop(ctx context.Context, health cell.Health) error {
	if m.nodeNeighbors == nil || !m.nodeNeighbors.NodeNeighDiscoveryEnabled() || option.Config.ARPPingRefreshPeriod == 0 || option.Config.ARPPingKernelManaged {
		return nil
	}

	neighRefreshTimer, neighRefreshTimerDone := inctimer.New()
	defer neighRefreshTimerDone()
	neighRefreshWatch := neighRefreshTimer.After(m.conf.ARPPingRefreshPeriod)

	neighRefreshTicker := time.NewTicker(50 * time.Millisecond)
	defer neighRefreshTicker.Stop()

	neighToRefresh := map[nodeTypes.Identity]time.Time{}

	refreshErrors := map[nodeTypes.Identity]error{}

	health = health.NewScope("neighbors")
	defer health.Close()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-neighRefreshWatch:
			// Queue refreshes for yet unrefreshed neighbors.
			neighRefreshWatch = neighRefreshTimer.After(m.conf.ARPPingRefreshPeriod)
			iter, _ := m.nodesTable.All(m.db.ReadTxn())
			for n, _, ok := iter.Next(); ok; n, _, ok = iter.Next() {
				if n.IsLocal() {
					continue
				}
				id := n.Identity()
				if _, ok := neighToRefresh[id]; !ok {
					// To avoid flooding network with arping requests
					// at the same time, spread them over the
					// [0; ARPPingRefreshPeriod/2) period.
					duration := rand.Int63n(int64(m.conf.ARPPingRefreshPeriod / 2))
					neighToRefresh[id] = time.Now().Add(time.Duration(duration))
				}
			}

		case <-neighRefreshTicker.C:
			if len(neighToRefresh) == 0 {
				continue
			}
			txn := m.db.ReadTxn()
			now := time.Now()
			refreshed := false

			for id, refreshAt := range neighToRefresh {
				if refreshAt.After(now) {
					continue
				}
				delete(neighToRefresh, id)

				node, _, ok := m.nodesTable.Get(txn, node.NodeIdentityIndex.Query(id))
				if !ok {
					// Node has been removed.
					delete(refreshErrors, id)
					continue
				}

				log.Debugf("Refreshing node neighbor link for %s", node.Name())
				err := m.nodeNeighbors.NodeNeighborRefresh(ctx, node.GetNode(), false)
				if err != nil {
					refreshErrors[id] = err
				} else {
					delete(refreshErrors, id)
				}
				refreshed = true
			}

			if refreshed {
				if len(refreshErrors) > 0 {
					health.Degraded("Node neighbor refresh failed", errors.Join(maps.Values(refreshErrors)...))
				} else {
					health.OK("Node neighbor refresh successful")
				}
			}
		}
	}
}

// NodeUpdated is called after the information of a node has been updated. The
// node in the manager is added or updated if the source is allowed to update
// the node. If an update or addition has occurred, NodeUpdate() of the datapath
// interface is invoked.
func (m *manager) NodeUpdated(n nodeTypes.Node) {
	log.WithFields(logrus.Fields{
		logfields.ClusterName: n.Cluster,
		logfields.NodeName:    n.Name,
		logfields.SPI:         n.EncryptionKey,
	}).Info("Node updated")
	if log.Logger.IsLevelEnabled(logrus.DebugLevel) {
		log.WithField(logfields.Node, n.LogRepr()).Debugf("Received node update event from %s", n.Source)
	}

	nodeIdentifier := n.Identity()

	var ipsetEntries []netip.Prefix
	for _, address := range n.IPAddresses {
		prefix := ip.IPToNetPrefix(address.IP)

		if address.Type == addressing.NodeInternalIP && !m.ipsetFilter(&n) {
			ipsetEntries = append(ipsetEntries, prefix)
		}
	}

	var v4Addrs, v6Addrs []netip.Addr
	for _, prefix := range ipsetEntries {
		addr := prefix.Addr()
		if addr.Is6() {
			v6Addrs = append(v6Addrs, addr)
		} else {
			v4Addrs = append(v4Addrs, addr)
		}
	}
	m.ipsetMgr.AddToIPSet(ipset.CiliumNodeIPSetV4, ipset.INetFamily, v4Addrs...)
	m.ipsetMgr.AddToIPSet(ipset.CiliumNodeIPSetV6, ipset.INet6Family, v6Addrs...)

	txn := m.db.WriteTxn(m.nodesTable)
	defer txn.Commit()

	oldNode, _, oldNodeExists := m.nodesTable.Get(txn, node.NodeIdentityIndex.Query(nodeIdentifier))

	if oldNodeExists {
		m.metrics.EventsReceived.WithLabelValues("update", string(n.Source)).Inc()

		if !source.AllowOverwrite(oldNode.Source(), n.Source) {
			// Done; skip node-handler updates and label injection
			// triggers below. Includes case where the local host
			// was discovered locally and then is subsequently
			// updated by the k8s watcher.
			return
		}

		newNode, err := oldNode.Builder().ModifyNode(func(node *nodeTypes.Node) { *node = n }).Build()
		if err == nil {
			m.nodesTable.Insert(txn, newNode)
		} else {
			log.WithError(err).WithField(logfields.Node, n.Name).Warn("Ignoring update for node")
		}

		m.cleanupIPSets(oldNode.GetNode(), ipsetEntries)
	} else {
		m.metrics.EventsReceived.WithLabelValues("add", string(n.Source)).Inc()
		m.nodesTable.Insert(txn, node.NewTableNode(n, nil))
	}
}

func (m *manager) cleanupIPSets(oldNode nodeTypes.Node, ipsetEntries []netip.Prefix) {
	var v4Addrs, v6Addrs []netip.Addr
	for _, address := range oldNode.IPAddresses {
		oldPrefix := ip.IPToNetPrefix(address.IP)
		if slices.Contains(ipsetEntries, oldPrefix) {
			continue
		}

		if address.Type == addressing.NodeInternalIP && !slices.Contains(ipsetEntries, oldPrefix) {
			addr, ok := ip.AddrFromIP(address.IP)
			if !ok {
				log.WithField(logfields.IPAddr, address.IP).Error("unable to convert to netip.Addr")
				continue
			}
			if addr.Is6() {
				v6Addrs = append(v6Addrs, addr)
			} else {
				v4Addrs = append(v4Addrs, addr)
			}
		}
	}

	m.ipsetMgr.RemoveFromIPSet(ipset.CiliumNodeIPSetV4, v4Addrs...)
	m.ipsetMgr.RemoveFromIPSet(ipset.CiliumNodeIPSetV6, v6Addrs...)
}

// NodeDeleted is called after a node has been deleted. It removes the node
// from the manager if the node is still owned by the source of which the event
// origins from. If the node was removed, NodeDelete() is invoked of the
// datapath interface.
func (m *manager) NodeDeleted(n nodeTypes.Node) {
	log.WithFields(logrus.Fields{
		logfields.ClusterName: n.Cluster,
		logfields.NodeName:    n.Name,
	}).Info("Node deleted")
	if log.Logger.IsLevelEnabled(logrus.DebugLevel) {
		log.Debugf("Received node delete event from %s", n.Source)
	}

	m.metrics.EventsReceived.WithLabelValues("delete", string(n.Source)).Inc()

	nodeIdentifier := n.Identity()

	txn := m.db.WriteTxn(m.nodesTable)
	defer txn.Commit()
	oldNode, _, oldNodeExists := m.nodesTable.Get(txn, node.NodeIdentityIndex.Query(nodeIdentifier))
	if !oldNodeExists {
		return
	}

	// If the source is Kubernetes and the node is the node we are running on
	// Kubernetes is giving us a hint it is about to delete our node. Close down
	// the agent gracefully in this case.
	if n.Source != oldNode.Source() {
		if n.IsLocal() && n.Source == source.Kubernetes {
			log.Debugf("Kubernetes is deleting local node, close manager")
			m.Stop(context.Background())
		} else {
			log.Debugf("Ignoring delete event of node %s from source %s. The node is owned by %s",
				n.Name, n.Source, oldNode.Source())
		}
		return
	}

	m.cleanupIPSets(oldNode.GetNode(), nil)

	m.nodesTable.Delete(txn, oldNode)
}

// NodeSync signals the manager that the initial nodes listing (either from k8s or kvstore)
// has been completed. This allows the manager to initiate the deletion of possible stale entries
// in the kernel IP sets managed by Cilium.
func (m *manager) NodeSync() {
	m.ipsetInitializer.InitDone()

	txn := m.db.WriteTxn(m.nodesTable)
	m.markTableInitialized(txn)
	txn.Commit()
}

// GetNodeIdentities returns a list of all node identities store in node
// manager.
func (m *manager) GetNodeIdentities() []nodeTypes.Identity {
	txn := m.db.ReadTxn()
	numNodes := m.nodesTable.NumObjects(txn)
	iter, _ := m.nodesTable.All(m.db.ReadTxn())

	nodes := make([]nodeTypes.Identity, 0, numNodes)
	for node, _, ok := iter.Next(); ok; node, _, ok = iter.Next() {
		nodes = append(nodes, node.Identity())
	}

	return nodes
}

// GetNodes returns a copy of all of the nodes as a map from Identity to Node.
func (m *manager) GetNodes() map[nodeTypes.Identity]nodeTypes.Node {
	txn := m.db.ReadTxn()
	numNodes := m.nodesTable.NumObjects(txn)
	iter, _ := m.nodesTable.All(m.db.ReadTxn())
	nodes := make(map[nodeTypes.Identity]nodeTypes.Node, numNodes)
	for node, _, ok := iter.Next(); ok; node, _, ok = iter.Next() {
		nodes[node.Identity()] = node.GetNode()
	}
	return nodes
}
