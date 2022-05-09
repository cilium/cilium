// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"math"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/source"
)

var (
	baseBackgroundSyncInterval = time.Minute
	randGen                    = rand.NewSafeRand(time.Now().UnixNano())
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
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (bool, error)
	Delete(IP string, source source.Source) bool
	TriggerLabelInjection(source source.Source)
	UpsertMetadata(string, labels.Labels)
}

// Configuration is the set of configuration options the node manager depends
// on
type Configuration interface {
	TunnelingEnabled() bool
	RemoteNodeIdentitiesEnabled() bool
	NodeEncryptionEnabled() bool
	EncryptionEnabled() bool
}

// Notifier is the interface the wraps Subscribe and Unsubscribe. An
// implementation of this interface notifies subscribers of nodes being added,
// updated or deleted.
type Notifier interface {
	// Subscribe adds the given NodeHandler to the list of subscribers that are
	// notified of node changes. Upon call to this method, the NodeHandler is
	// being notified of all nodes that are already in the cluster by calling
	// the NodeHandler's NodeAdd callback.
	Subscribe(datapath.NodeHandler)
	// Unsubscribe removes the given NodeHandler from the list of subscribers.
	Unsubscribe(datapath.NodeHandler)
}

var _ Notifier = (*Manager)(nil)

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
	nodes map[nodeTypes.Identity]*nodeEntry

	// nodeHandlersMu protects the nodeHandlers map against concurrent access.
	nodeHandlersMu lock.RWMutex
	// nodeHandlers has a slice containing all node handlers subscribed to node
	// events.
	nodeHandlers map[datapath.NodeHandler]struct{}

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

	// conf is the configuration of the caller passed in via NewManager.
	// This field is immutable after NewManager()
	conf Configuration

	// ipcache is the set operations performed against the ipcache
	ipcache IPCache

	// controllerManager manages the controllers that are launched within the
	// Manager.
	controllerManager *controller.Manager

	// selectorCacheUpdater updates the identities inside the selector cache.
	selectorCacheUpdater selectorCacheUpdater

	// policyTriggerer triggers policy updates (recalculations).
	policyTriggerer policyTriggerer
}

type selectorCacheUpdater interface {
	UpdateIdentities(added, deleted cache.IdentityCache, wg *sync.WaitGroup)
}

type policyTriggerer interface {
	UpdatePolicyMaps(context.Context, *sync.WaitGroup) *sync.WaitGroup
}

// Subscribe subscribes the given node handler to node events.
func (m *Manager) Subscribe(nh datapath.NodeHandler) {
	m.nodeHandlersMu.Lock()
	m.nodeHandlers[nh] = struct{}{}
	m.nodeHandlersMu.Unlock()
	// Add all nodes already received by the manager.
	m.mutex.RLock()
	for _, v := range m.nodes {
		v.mutex.Lock()
		nh.NodeAdd(v.node)
		v.mutex.Unlock()
	}
	m.mutex.RUnlock()
}

// Unsubscribe unsubscribes the given node handler with node events.
func (m *Manager) Unsubscribe(nh datapath.NodeHandler) {
	m.nodeHandlersMu.Lock()
	delete(m.nodeHandlers, nh)
	m.nodeHandlersMu.Unlock()
}

// Iter executes the given function in all subscribed node handlers.
func (m *Manager) Iter(f func(nh datapath.NodeHandler)) {
	m.nodeHandlersMu.RLock()
	defer m.nodeHandlersMu.RUnlock()

	for nh := range m.nodeHandlers {
		f(nh)
	}
}

// NewManager returns a new node manager
func NewManager(name string, dp datapath.NodeHandler, c Configuration, sc selectorCacheUpdater, pt policyTriggerer) (*Manager, error) {
	m := &Manager{
		name:                 name,
		nodes:                map[nodeTypes.Identity]*nodeEntry{},
		conf:                 c,
		controllerManager:    controller.NewManager(),
		selectorCacheUpdater: sc,
		policyTriggerer:      pt,
		nodeHandlers:         map[datapath.NodeHandler]struct{}{},
		closeChan:            make(chan struct{}),
	}
	m.Subscribe(dp)

	m.metricEventsReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: "nodes",
		Name:      name + "_events_received_total",
		Help:      "Number of node events received",
	}, []string{"event_type", "source"})

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
		Help:      "Number of validation calls to implement the datapath implementation of a node",
	})

	err := metrics.RegisterList([]prometheus.Collector{m.metricDatapathValidations, m.metricEventsReceived, m.metricNumNodes})
	if err != nil {
		return nil, err
	}

	go m.backgroundSync()

	return m, nil
}

// WithSelectorCacheUpdater sets the selector cache updater in the Manager.
func (m *Manager) WithSelectorCacheUpdater(sc selectorCacheUpdater) *Manager {
	m.selectorCacheUpdater = sc
	return m
}

// WithPolicyTriggerer sets the policy update trigger in the Manager.
func (m *Manager) WithPolicyTriggerer(pt policyTriggerer) *Manager {
	m.policyTriggerer = pt
	return m
}

// WithIPCache sets the ipcache field in the Manager.
func (m *Manager) WithIPCache(ipc IPCache) *Manager {
	m.ipcache = ipc
	return m
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
		m.Iter(func(nh datapath.NodeHandler) {
			nh.NodeDelete(n.node)
		})
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

// backgroundSync ensures that local node has a valid datapath in-place for
// each node in the cluster. See NodeValidateImplementation().
func (m *Manager) backgroundSync() {
	syncTimer, syncTimerDone := inctimer.New()
	defer syncTimerDone()
	for {
		syncInterval := m.backgroundSyncInterval()
		log.WithField("syncInterval", syncInterval.String()).Debug("Performing regular background work")

		// get a copy of the node identities to avoid locking the entire manager
		// throughout the process of running the datapath validation.
		nodes := m.GetNodeIdentities()
		for _, nodeIdentity := range nodes {
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
			m.Iter(func(nh datapath.NodeHandler) {
				nh.NodeValidateImplementation(entry.node)
			})
			entry.mutex.Unlock()

			m.metricDatapathValidations.Inc()
		}

		select {
		case <-m.closeChan:
			return
		case <-syncTimer.After(syncInterval):
		}
	}
}

// legacyNodeIpBehavior returns true if the agent is still running in legacy
// mode regarding node IPs
func (m *Manager) legacyNodeIpBehavior() bool {
	// Cilium < 1.7 only exposed the Cilium internalIP to the ipcache
	// unless encryption was enabled. This meant that for the majority of
	// node IPs, CIDR policy rules would apply. With the introduction of
	// remote-node identities, all node IPs were suddenly added to the
	// ipcache. This resulted in a behavioral change. New deployments will
	// provide this behavior out of the gate, existing deployments will
	// have to opt into this by enabling remote-node identities.
	if m.conf.RemoteNodeIdentitiesEnabled() {
		return false
	}
	// Needed to store the SPI for nodes in the ipcache.
	if m.conf.NodeEncryptionEnabled() {
		return false
	}
	// Needed to store the SPI for pod->remote node in the ipcache since
	// that path goes through the tunnel.
	if m.conf.EncryptionEnabled() && m.conf.TunnelingEnabled() {
		return false
	}
	return true
}

// NodeUpdated is called after the information of a node has been updated. The
// node in the manager is added or updated if the source is allowed to update
// the node. If an update or addition has occurred, NodeUpdate() of the datapath
// interface is invoked.
func (m *Manager) NodeUpdated(n nodeTypes.Node) {
	log.Debugf("Received node update event from %s: %#v", n.Source, n)

	nodeIdentity := n.Identity()
	dpUpdate := true
	nodeIP := n.GetNodeIP(false)

	remoteHostIdentity := identity.ReservedIdentityHost
	if m.conf.RemoteNodeIdentitiesEnabled() {
		nid := identity.NumericIdentity(n.NodeIdentity)
		if nid != identity.IdentityUnknown && nid != identity.ReservedIdentityHost {
			remoteHostIdentity = nid
		} else if !n.IsLocal() {
			remoteHostIdentity = identity.ReservedIdentityRemoteNode
		}
	}

	var ipsAdded, healthIPsAdded, ingressIPsAdded []string

	// helper function with the required logic to skip IPCache interactions
	skipIPCache := func(address nodeTypes.Address) bool {
		return m.legacyNodeIpBehavior() && address.Type != addressing.NodeCiliumInternalIP
	}

	for _, address := range n.IPAddresses {
		var tunnelIP net.IP
		key := n.EncryptionKey

		// If the host firewall is enabled, all traffic to remote nodes must go
		// through the tunnel to preserve the source identity as part of the
		// encapsulation. In encryption case we also want to use vxlan device
		// to create symmetric traffic when sending nodeIP->pod and pod->nodeIP.
		if address.Type == addressing.NodeCiliumInternalIP || m.conf.EncryptionEnabled() ||
			option.Config.EnableHostFirewall || option.Config.JoinCluster {
			tunnelIP = nodeIP
		}

		if option.Config.NodeIpsetNeeded() && address.Type == addressing.NodeInternalIP {
			iptables.AddToNodeIpset(address.IP)
		}

		if skipIPCache(address) {
			continue
		}

		// If we are doing encryption, but not node based encryption, then do not
		// add a key to the nodeIPs so that we avoid a trip through stack and attempting
		// to encrypt something we know does not have an encryption policy installed
		// in the datapath. By setting key=0 and tunnelIP this will result in traffic
		// being sent unencrypted over overlay device.
		if !m.conf.NodeEncryptionEnabled() &&
			(address.Type == addressing.NodeExternalIP || address.Type == addressing.NodeInternalIP) {
			key = 0
		}

		ipAddrStr := address.IP.String()
		_, err := m.ipcache.Upsert(ipAddrStr, tunnelIP, key, nil, ipcache.Identity{
			ID:     remoteHostIdentity,
			Source: n.Source,
		})

		m.upsertIntoIDMD(ipAddrStr, remoteHostIdentity)

		// Upsert() will return true if the ipcache entry is owned by
		// the source of the node update that triggered this node
		// update (kvstore, k8s, ...) The datapath is only updated if
		// that source of truth is updated.
		if err != nil {
			dpUpdate = false
		} else {
			ipsAdded = append(ipsAdded, ipAddrStr)
		}
	}

	for _, address := range []net.IP{n.IPv4HealthIP, n.IPv6HealthIP} {
		if address == nil {
			continue
		}
		addrStr := address.String()
		_, err := m.ipcache.Upsert(addrStr, nodeIP, n.EncryptionKey, nil, ipcache.Identity{
			ID:     identity.ReservedIdentityHealth,
			Source: n.Source,
		})
		if err != nil {
			dpUpdate = false
		} else {
			healthIPsAdded = append(healthIPsAdded, addrStr)
		}
	}

	for _, address := range []net.IP{n.IPv4IngressIP, n.IPv6IngressIP} {
		if address == nil {
			continue
		}
		addrStr := address.String()
		_, err := m.ipcache.Upsert(addrStr, nodeIP, n.EncryptionKey, nil, ipcache.Identity{
			ID:     identity.ReservedIdentityIngress,
			Source: n.Source,
		})
		if err != nil {
			dpUpdate = false
		} else {
			ingressIPsAdded = append(ingressIPsAdded, addrStr)
		}
	}

	m.mutex.Lock()
	entry, oldNodeExists := m.nodes[nodeIdentity]
	if oldNodeExists {
		m.metricEventsReceived.WithLabelValues("update", string(n.Source)).Inc()

		if !source.AllowOverwrite(entry.node.Source, n.Source) {
			// Done; skip node-handler updates and label injection
			// triggers below. Includes case where the local host
			// was discovered locally and then is subsequently
			// updated by the k8s watcher.
			m.mutex.Unlock()
			return
		}

		entry.mutex.Lock()
		m.mutex.Unlock()
		oldNode := entry.node
		entry.node = n
		if dpUpdate {
			m.Iter(func(nh datapath.NodeHandler) {
				nh.NodeUpdate(oldNode, entry.node)
			})
		}
		// Delete the old node IP addresses if they have changed in this node.
		var oldNodeIPAddrs []net.IP
		for _, address := range oldNode.IPAddresses {
			if skipIPCache(address) {
				continue
			}
			oldNodeIPAddrs = append(oldNodeIPAddrs, address.IP)
		}
		m.deleteIPCache(oldNode.Source, oldNodeIPAddrs, ipsAdded)

		// Delete the old health IP addresses if they have changed in this node.
		m.deleteIPCache(oldNode.Source, []net.IP{oldNode.IPv4HealthIP, oldNode.IPv6HealthIP}, healthIPsAdded)

		// Delete the old ingress IP addresses if they have changed in this node.
		m.deleteIPCache(oldNode.Source, []net.IP{oldNode.IPv4IngressIP, oldNode.IPv6IngressIP}, ingressIPsAdded)

		entry.mutex.Unlock()
	} else {
		m.metricEventsReceived.WithLabelValues("add", string(n.Source)).Inc()
		m.metricNumNodes.Inc()

		entry = &nodeEntry{node: n}
		entry.mutex.Lock()
		m.nodes[nodeIdentity] = entry
		m.mutex.Unlock()
		if dpUpdate {
			m.Iter(func(nh datapath.NodeHandler) {
				nh.NodeAdd(entry.node)
			})
		}
		entry.mutex.Unlock()
	}

	m.ipcache.TriggerLabelInjection(n.Source)
}

// upsertIntoIDMD upserts the given CIDR into the ipcache.identityMetadata
// (IDMD) map. The given node identity determines which labels are associated
// with the CIDR.
func (m *Manager) upsertIntoIDMD(prefix string, id identity.NumericIdentity) {
	if id == identity.ReservedIdentityHost {
		m.ipcache.UpsertMetadata(prefix, labels.LabelHost)
	} else {
		m.ipcache.UpsertMetadata(prefix, labels.LabelRemoteNode)
	}
}

// deleteIPCache deletes the IP addresses from the IPCache with the 'oldSource'
// if they are not found in the newIPs slice.
func (m *Manager) deleteIPCache(oldSource source.Source, oldIPs []net.IP, newIPs []string) {
	for _, address := range oldIPs {
		if address == nil {
			continue
		}
		addrStr := address.String()
		var found bool
		for _, ipAdded := range newIPs {
			if ipAdded == addrStr {
				found = true
				break
			}
		}
		// Delete from the IPCache if the node's IP addresses was not
		// added in this update.
		if !found {
			m.ipcache.Delete(addrStr, oldSource)
		}
	}
}

// NodeDeleted is called after a node has been deleted. It removes the node
// from the manager if the node is still owned by the source of which the event
// origins from. If the node was removed, NodeDelete() is invoked of the
// datapath interface.
func (m *Manager) NodeDeleted(n nodeTypes.Node) {
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
		if n.IsLocal() && n.Source == source.Kubernetes {
			log.Debugf("Kubernetes is deleting local node, close manager")
			m.Close()
		} else {
			log.Debugf("Ignoring delete event of node %s from source %s. The node is owned by %s",
				n.Name, n.Source, entry.node.Source)
		}
		return
	}

	for _, address := range entry.node.IPAddresses {
		if option.Config.NodeIpsetNeeded() && address.Type == addressing.NodeInternalIP {
			iptables.RemoveFromNodeIpset(address.IP)
		}

		if m.legacyNodeIpBehavior() && address.Type != addressing.NodeCiliumInternalIP {
			continue
		}

		m.ipcache.Delete(address.IP.String(), n.Source)
	}

	for _, address := range []net.IP{
		entry.node.IPv4HealthIP, entry.node.IPv6HealthIP,
		entry.node.IPv4IngressIP, entry.node.IPv6IngressIP,
	} {
		if address != nil {
			m.ipcache.Delete(address.String(), n.Source)
		}
	}

	m.metricNumNodes.Dec()

	entry.mutex.Lock()
	delete(m.nodes, nodeIdentity)
	m.mutex.Unlock()
	m.Iter(func(nh datapath.NodeHandler) {
		nh.NodeDelete(n)
	})
	entry.mutex.Unlock()
}

// GetNodeIdentities returns a list of all node identities store in node
// manager.
func (m *Manager) GetNodeIdentities() []nodeTypes.Identity {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	nodes := make([]nodeTypes.Identity, 0, len(m.nodes))
	for nodeIdentity := range m.nodes {
		nodes = append(nodes, nodeIdentity)
	}

	return nodes
}

// GetNodes returns a copy of all of the nodes as a map from Identity to Node.
func (m *Manager) GetNodes() map[nodeTypes.Identity]nodeTypes.Node {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	nodes := make(map[nodeTypes.Identity]nodeTypes.Node)
	for nodeIdentity, entry := range m.nodes {
		entry.mutex.Lock()
		nodes[nodeIdentity] = entry.node
		entry.mutex.Unlock()
	}

	return nodes
}

// StartNeighborRefresh spawns a controller which refreshes neighbor table
// by sending arping periodically.
func (m *Manager) StartNeighborRefresh(nh datapath.NodeHandler) {
	ctx, cancel := context.WithCancel(context.Background())
	controller.NewManager().UpdateController("neighbor-table-refresh",
		controller.ControllerParams{
			DoFunc: func(controllerCtx context.Context) error {
				// Cancel previous go routines from previous controller run
				cancel()
				ctx, cancel = context.WithCancel(controllerCtx)
				m.mutex.RLock()
				defer m.mutex.RUnlock()
				for _, entry := range m.nodes {
					entry.mutex.Lock()
					entryNode := entry.node
					entry.mutex.Unlock()
					if entryNode.IsLocal() {
						continue
					}
					go func(c context.Context, e nodeTypes.Node) {
						// To avoid flooding network with arping requests
						// at the same time, spread them over the
						// [0; ARPPingRefreshPeriod/2) period.
						n := randGen.Int63n(int64(option.Config.ARPPingRefreshPeriod / 2))
						time.Sleep(time.Duration(n))
						nh.NodeNeighborRefresh(c, e)
					}(ctx, entryNode)
				}
				return nil
			},
			RunInterval: option.Config.ARPPingRefreshPeriod,
		},
	)
	return
}
