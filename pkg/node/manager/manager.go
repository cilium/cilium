// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
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

var _ Notifier = (*manager)(nil)

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
	nodeMetrics *nodeMetrics,
	health cell.Health,
	jobGroup job.Group,
	db *statedb.DB,
	devices statedb.Table[*tables.Device],
	writer *node.Writer,
	clusterSizeDependantInterval node.ClusterSizeDependantIntervalFunc,
) (*manager, error) {
	m := &manager{
		logger:                       logger,
		nodes:                        map[nodeTypes.Identity]*nodeEntry{},
		writer:                       writer,
		controllerManager:            controller.NewManager(),
		nodeHandlers:                 map[node.Handler]struct{}{},
		metrics:                      nodeMetrics,
		health:                       health,
		jobGroup:                     jobGroup,
		clusterSizeDependantInterval: clusterSizeDependantInterval,
		db:                           db,
		devices:                      devices,
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

// NodeUpdated is called after the information of a node has been updated. The
// node in the manager is added or updated if the source is allowed to update
// the node. If an update or addition has occurred, NodeUpdate() of the datapath
// interface is invoked.
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
		oldNode := entry.node
		entry.node = n
		m.upsertToNodeTable(&entry.node)

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
		entry.mutex.Unlock()
	} else {
		m.metrics.EventsReceived.WithLabelValues("add", string(n.Source)).Inc()
		m.metrics.NumNodes.Inc()

		entry = &nodeEntry{node: n}
		entry.mutex.Lock()
		m.nodes[nodeIdentifier] = entry
		m.upsertToNodeTable(&entry.node)
		m.mutex.Unlock()

		var errs error
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
		entry.mutex.Unlock()

		hr := m.health.NewScope("nodes-add")
		if errs != nil {
			hr.Degraded("Failed to add nodes", errs)
		} else {
			hr.OK("Node adds successful")
		}
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

// NodeDeleted is called after a node has been deleted. It removes the node
// from the manager if the node is still owned by the source of which the event
// origins from. If the node was removed, NodeDelete() is invoked of the
// datapath interface.
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

	// If the source is Kubernetes and the node is the node we are running on
	// Kubernetes is giving us a hint it is about to delete our node. Close down
	// the agent gracefully in this case.
	if n.Source != entry.node.Source {
		m.mutex.Unlock()
		if n.IsLocal() && n.Source == source.Kubernetes {
			m.logger.Debug(
				"Kubernetes is deleting local node, close manager",
			)
			m.Stop(context.Background())
		} else {
			m.logger.Debug(
				"Ignoring delete event of node",
				logfields.Name, n.Name,
				logfields.Source, n.Source,
				logfields.NodeOwner, entry.node.Source,
			)
		}
		return
	}

	m.metrics.NumNodes.Dec()

	entry.mutex.Lock()
	delete(m.nodes, nodeIdentifier)
	m.deleteFromNodeTable(n.Source, nodeIdentifier)
	m.mutex.Unlock()
	var errs error
	m.Iter(func(nh node.Handler) {
		if err := nh.NodeDelete(n); err != nil {
			// For now we log the error and continue. Eventually we will want to encorporate
			// this into the node managers health status.
			// However this is a bit tricky - as leftover node deletes are not retries so this will
			// need to be accompanied by some kind of retry mechanism.
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
