// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package manager

import (
	"math"
	"time"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	baseBackgroundSyncInterval = time.Minute
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
	node  node.Node
}

// Manager is the entity that manages a collection of nodes
type Manager struct {
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
	nodes map[node.Identity]*nodeEntry

	// datapath is the interface responsible for this node manager
	datapath datapath.NodeHandler

	// closeChan is closed when the manager is closed
	closeChan chan struct{}

	// name is the name of the manager. It must be unique and feasibility
	// to be used a prometheus metric name.
	name string

	// metricEventsReceived is the prometheus metric to track the number of
	// node events received
	metricEventsReceived *prometheus.CounterVec

	// metricNumNodes is the prometheus metric to track the number of nodes
	// being managed
	metricNumNodes prometheus.Gauge

	// metricDatapathValidations is the prometheus metric to track the
	// number of datapath node validation calls
	metricDatapathValidations prometheus.Counter
}

// NewManager returns a new node manager
func NewManager(name string, datapath datapath.NodeHandler) (*Manager, error) {
	m := &Manager{
		name:      name,
		nodes:     map[node.Identity]*nodeEntry{},
		datapath:  datapath,
		closeChan: make(chan struct{}),
	}

	m.metricEventsReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: "nodes",
		Name:      name + "_events_received_total",
		Help:      "Number of node events received",
	}, []string{"eventType", "source"})

	m.metricNumNodes = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metrics.Namespace,
		Subsystem: "nodes",
		Name:      name + "_num",
		Help:      "Number of nodes managed",
	})

	m.metricDatapathValidations = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: "nodes",
		Name:      name + "_datapath_validations_total",
		Help:      "Number of validation calls to implement the datapath implemention of a node",
	})

	err := metrics.RegisterList([]prometheus.Collector{m.metricDatapathValidations, m.metricEventsReceived, m.metricNumNodes})
	if err != nil {
		return nil, err
	}

	go m.backgroundSync()

	return m, nil
}

// Close shuts down a node manager
func (m *Manager) Close() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	close(m.closeChan)

	metrics.Unregister(m.metricNumNodes)
	metrics.Unregister(m.metricEventsReceived)
	metrics.Unregister(m.metricDatapathValidations)

	// delete all nodes to clean up the datapath for each node
	for _, n := range m.nodes {
		n.mutex.Lock()
		m.datapath.NodeDelete(n.node)
		n.mutex.Unlock()
	}
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
func (m *Manager) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	m.mutex.RLock()
	numNodes := len(m.nodes)
	m.mutex.RUnlock()

	// no nodes are being managed, no work will be performed, return
	// baseInterval to check again in a reasonable timeframe
	if numNodes == 0 {
		return baseInterval
	}

	waitNanoseconds := float64(baseInterval.Nanoseconds()) * math.Log1p(float64(numNodes))
	return time.Duration(int64(waitNanoseconds))

}

func (m *Manager) backgroundSyncInterval() time.Duration {
	return m.ClusterSizeDependantInterval(baseBackgroundSyncInterval)
}

func (m *Manager) backgroundSync() {
	for {
		syncInterval := m.backgroundSyncInterval()
		log.WithField("syncInterval", syncInterval.String()).Debug("Performing regular background work")

		// get a copy of the nodes to avoid locking the entire manager
		// throughout the process of running the datapath validation.
		nodes := m.GetNodes()
		for nodeIdentity := range nodes {
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
			m.datapath.NodeValidateImplementation(entry.node)
			entry.mutex.Unlock()

			m.metricDatapathValidations.Inc()
		}

		select {
		case <-m.closeChan:
			return
		case <-time.After(syncInterval):
		}
	}
}

// overwriteAllowed returns true if an update from newSource can overwrite a node owned by oldSource.
func overwriteAllowed(oldSource, newSource node.Source) bool {
	switch newSource {
	// the local node always takes precedence
	case node.FromLocalNode:
		return true

	// agent local updates can overwrite everything except for the local
	// node
	case node.FromAgentLocal:
		return oldSource != node.FromLocalNode

	// kvstore updates can overwrite everything except agent local updates and local node
	case node.FromKVStore:
		return oldSource != node.FromAgentLocal && oldSource != node.FromLocalNode

	// kubernetes updates can only overwrite kubernetes nodes
	case node.FromKubernetes:
		return oldSource != node.FromAgentLocal && oldSource != node.FromLocalNode && oldSource != node.FromKVStore

	default:
		return false
	}
}

// NodeSoftUpdated is called after the information of a node has be upated but
// unlike a NodeUpdated does not require the datapath to be updated.
func (m *Manager) NodeSoftUpdated(n node.Node) {
	log.Debugf("Received soft node update event from %s: %#v", n.Source, n)
	m.nodeUpdated(n, false)
}

// NodeUpdated is called after the information of a node has been updated. The
// node in the manager is added or updated if the source is allowed to update
// the node. If an update or addition has occured, NodeUpdate() of the datapath
// interface is invoked.
func (m *Manager) NodeUpdated(n node.Node) {
	log.Debugf("Received node update event from %s: %#v", n.Source, n)
	m.nodeUpdated(n, true)
}

func (m *Manager) nodeUpdated(n node.Node, dpUpdate bool) {
	nodeIdentity := n.Identity()

	m.mutex.Lock()
	entry, oldNodeExists := m.nodes[nodeIdentity]
	if oldNodeExists {
		m.metricEventsReceived.WithLabelValues("update", string(n.Source)).Inc()

		if !overwriteAllowed(entry.node.Source, n.Source) {
			m.mutex.Unlock()
			return
		}

		entry.mutex.Lock()
		m.mutex.Unlock()
		oldNode := entry.node
		entry.node = n
		if dpUpdate {
			m.datapath.NodeUpdate(oldNode, entry.node)
		}
		entry.mutex.Unlock()
	} else {
		m.metricEventsReceived.WithLabelValues("add", string(n.Source)).Inc()
		m.metricNumNodes.Inc()

		entry = &nodeEntry{node: n}
		entry.mutex.Lock()
		m.nodes[nodeIdentity] = entry
		m.mutex.Unlock()
		if dpUpdate {
			m.datapath.NodeAdd(entry.node)
		}
		entry.mutex.Unlock()
	}
}

// NodeDeleted is called after a node has been deleted. It removes the node
// from the manager if the node is still owned by the source of which the event
// orgins from. If the node was removed, NodeDelete() is invoked of the
// datapath interface.
func (m *Manager) NodeDeleted(n node.Node) {
	m.metricEventsReceived.WithLabelValues("delete", string(n.Source)).Inc()

	log.Debugf("Received node delete event from %s", n.Source)

	nodeIdentity := n.Identity()

	m.mutex.Lock()
	entry, oldNodeExists := m.nodes[nodeIdentity]
	if !oldNodeExists {
		m.mutex.Unlock()
		return
	}

	// If the source is Kubernetes and the node is the node we are running on
	// Kubernetes is giving us a hint it is about to delete our node. Close down
	// the agent gracefully in this case.
	if n.Source != entry.node.Source {
		m.mutex.Unlock()
		if n.IsLocal() && n.Source == node.FromKubernetes {
			log.Debugf("Kubernetes is deleting local node, close manager")
			m.Close()
		} else {
			log.Debugf("Ignoring delete event of node %s from source %s. The node is owned by %s",
				n.Name, n.Source, entry.node.Source)
		}
		return
	}

	m.metricNumNodes.Dec()

	entry.mutex.Lock()
	delete(m.nodes, nodeIdentity)
	m.mutex.Unlock()
	m.datapath.NodeDelete(n)
	entry.mutex.Unlock()
}

// GetNodes returns a copy of all of the nodes as a map from Identity to Node.
func (m *Manager) GetNodes() map[node.Identity]node.Node {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	nodes := make(map[node.Identity]node.Node)
	for nodeIdentity, entry := range m.nodes {
		entry.mutex.Lock()
		nodes[nodeIdentity] = entry.node
		entry.mutex.Unlock()
	}

	return nodes
}

// DeleteAllNodes deletes all nodes from the node maanger.
func (m *Manager) DeleteAllNodes() {
	m.mutex.Lock()
	for _, entry := range m.nodes {
		entry.mutex.Lock()
		m.datapath.NodeDelete(entry.node)
		entry.mutex.Unlock()
	}
	m.nodes = map[node.Identity]*nodeEntry{}
	m.mutex.Unlock()
}
