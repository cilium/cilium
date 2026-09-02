// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
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

// manager is the entity that manages a collection of nodes
type manager struct {
	logger *slog.Logger
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
	nodeMetrics *nodeMetrics,
	health cell.Health,
	jobGroup job.Group,
	db *statedb.DB,
	devices statedb.Table[*tables.Device],
	writer *node.Writer,
	clusterSizeDependantInterval node.ClusterSizeDependantIntervalFunc,
) (*manager, error) {
	m := &manager{
		logger:  logger,
		nodes:   map[nodeTypes.Identity]*nodeEntry{},
		writer:  writer,
		metrics: nodeMetrics,
		db:      db,
		devices: devices,
	}

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

// NodeUpdated is called after the information of a node has been updated. The
// node in the manager is added or updated if the source is allowed to update
// the node.
func (m *manager) NodeUpdated(n nodeTypes.Node) {
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
	m.mutex.Lock()
	entry, oldNodeExists := m.nodes[nodeIdentifier]
	if oldNodeExists {
		m.metrics.EventsReceived.WithLabelValues("update", string(n.Source)).Inc()

		if !source.AllowOverwrite(entry.node.Source, n.Source) {
			m.mutex.Unlock()
			return
		}

		entry.mutex.Lock()
		m.mutex.Unlock()
		entry.node = n
		m.upsertToNodeTable(&entry.node)
		entry.mutex.Unlock()
	} else {
		m.metrics.EventsReceived.WithLabelValues("add", string(n.Source)).Inc()
		m.metrics.NumNodes.Inc()

		entry = &nodeEntry{node: n}
		entry.mutex.Lock()
		m.nodes[nodeIdentifier] = entry
		m.upsertToNodeTable(&entry.node)
		m.mutex.Unlock()

		entry.mutex.Unlock()
	}
}

func (m *manager) upsertToNodeTable(n *nodeTypes.Node) {
	if n.IsLocal() || m.writer == nil {
		return
	}
	txn := m.db.WriteTxn(m.writer.Table())
	m.writer.Upsert(txn, n)
	txn.Commit()
}

func (m *manager) deleteFromNodeTable(src source.Source, nodeID nodeTypes.Identity) {
	if m.writer == nil {
		return
	}
	txn := m.db.WriteTxn(m.writer.Table())
	m.writer.Delete(txn, src, nodeID)
	txn.Commit()
}

// NodeDeleted removes a node if it is still owned by the source that emitted
// the event.
func (m *manager) NodeDeleted(n nodeTypes.Node) {
	m.logger.Info(
		"Node deleted",
		logfields.ClusterName, n.Cluster,
		logfields.NodeName, n.Name,
	)
	m.logger.Debug(
		"Received node delete event",
		logfields.Source, n.Source,
	)

	m.metrics.EventsReceived.WithLabelValues("delete", string(n.Source)).Inc()

	nodeIdentifier := n.Identity()

	var (
		entry         *nodeEntry
		oldNodeExists bool
	)

	m.mutex.Lock()
	entry, oldNodeExists = m.nodes[nodeIdentifier]
	if !oldNodeExists {
		m.mutex.Unlock()
		return
	}

	if n.Source != entry.node.Source {
		m.mutex.Unlock()
		m.logger.Debug(
			"Ignoring delete event of node",
			logfields.Name, n.Name,
			logfields.Source, n.Source,
			logfields.NodeOwner, entry.node.Source,
		)
		return
	}

	m.metrics.NumNodes.Dec()

	entry.mutex.Lock()
	delete(m.nodes, nodeIdentifier)
	m.deleteFromNodeTable(n.Source, nodeIdentifier)
	m.mutex.Unlock()
	entry.mutex.Unlock()
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
	if m.writer != nil {
		m.writer.SetPrefixClusterMutatorFn(mutator)
	}
}
