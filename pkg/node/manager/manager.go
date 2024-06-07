// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/renameio"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"golang.org/x/time/rate"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/trigger"
)

const NodesFilename = "nodes.json"

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
	UpsertLabels(prefix netip.Prefix, lbls labels.Labels, src source.Source, rid ipcacheTypes.ResourceID)
	RemoveLabels(prefix netip.Prefix, lbls labels.Labels, rid ipcacheTypes.ResourceID)
}

// Configuration is the set of configuration options the node manager depends
// on
type Configuration interface {
	TunnelingEnabled() bool
	RemoteNodeIdentitiesEnabled() bool
	NodeEncryptionEnabled() bool
	NodeIpsetNeeded() bool
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

	// Upon agent startup, this is filled with nodes as read from disk. Used to
	// synthesize node deletion events for nodes which disappeared while we were
	// down.
	restoredNodes map[nodeTypes.Identity]*nodeTypes.Node

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

	// persistNodesTrigger triggers writing the current set of nodes to disk
	persistNodesTrigger *trigger.Trigger
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
		restoredNodes:        map[nodeTypes.Identity]*nodeTypes.Node{},
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

	// Ensure that we read a potential nodes file before we overwrite it.
	m.readNodesFromDisk()
	if err := m.initializePersistNodeTrigger(); err != nil {
		return nil, fmt.Errorf("failed to initialize node persistence: %w", err)
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

	return backoff.ClusterSizeDependantInterval(baseInterval, numNodes)
}

func (m *Manager) backgroundSyncInterval() time.Duration {
	return m.ClusterSizeDependantInterval(baseBackgroundSyncInterval)
}

func (m *Manager) readNodesFromDisk() {
	f, err := os.Open(filepath.Join(option.Config.StateDir, NodesFilename))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// If we don't have a file to restore from, there's nothing we can
			// do. This is expected in the upgrade path.
			return
		}
		log.WithError(err).Error("failed to read nodes restoration file")
		return
	}

	r := json.NewDecoder(bufio.NewReader(f))
	var restoredNodes []*nodeTypes.Node
	if err := r.Decode(&restoredNodes); err != nil {
		log.WithError(err).Error("failed to decode node restoration file")
		return
	}

	// We can't call NodeUpdated for the restored nodes here, as the machinery
	// assumes a fully initialized node manager, which we don't currently have.
	// In addition, we only want to synthesize NodeDeletions not resurrect
	// potentially long-dead nodes. Therefore we keep the restored nodes
	// separate, let whatever init needs to happen occur and once we're synced
	// to k8s, compare the restored nodes to the live ones.
	for _, n := range restoredNodes {
		n.Source = source.Restored
		m.restoredNodes[n.Identity()] = n
	}
}

// PruneStaleNodes emits deletion events to subscribers for nodes which were
// deleted while the agent was down.
func (m *Manager) PruneStaleNodes() {
	m.mutex.RLock()
	for id := range m.nodes {
		delete(m.restoredNodes, id)
	}
	m.mutex.RUnlock()

	if len(m.restoredNodes) > 0 {
		log.WithFields(logrus.Fields{
			"stale-nodes": m.restoredNodes,
		}).Info("Deleting stale nodes")
	}

	// Delete nodes now considered stale.
	for _, n := range m.restoredNodes {
		m.NodeDeleted(*n)
	}
}

// initializePersistNodeTrigger sets up the node persistence machinery
func (m *Manager) initializePersistNodeTrigger() error {
	var err error
	m.persistNodesTrigger, err = trigger.NewTrigger(trigger.Parameters{
		MinInterval: 5 * time.Second, // TODO min interval?
		TriggerFunc: func(reasons []string) {
			m.mutex.RLock()
			defer m.mutex.RUnlock()

			if err := m.writeNodesToFile(option.Config.StateDir); err != nil {
				log.WithFields(logrus.Fields{
					logfields.Reason: reasons,
				}).WithError(err).Warning("could not write nodes file")
			}
		},
	})
	return err
}

// writeNodesToFile writes the node state to disk. Assumes the manager is locked.
func (m *Manager) writeNodesToFile(prefix string) error {
	nodesPath := filepath.Join(prefix, NodesFilename)
	log.WithFields(logrus.Fields{
		logfields.Path: nodesPath,
	}).Debug("writing nodes.json file")

	// Write new contents to a temporary file which will be atomically renamed to the
	// real file at the end of this function to avoid data corruption if we crash.
	f, err := renameio.TempFile(prefix, nodesPath)
	if err != nil {
		return fmt.Errorf("failed to open temporary file: %s", err)
	}
	defer f.Cleanup()

	bw := bufio.NewWriter(f)
	w := json.NewEncoder(bw)
	ns := make([]nodeTypes.Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		ns = append(ns, n.node)
	}
	if err := w.Encode(ns); err != nil {
		return fmt.Errorf("failed to json encode nodes: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	return f.CloseAtomicallyReplace()
}

// backgroundSync ensures that local node has a valid datapath in-place for
// each node in the cluster. See NodeValidateImplementation().
func (m *Manager) backgroundSync() {
	syncTimer, syncTimerDone := inctimer.New()
	defer syncTimerDone()
	for {
		syncInterval := m.backgroundSyncInterval()
		startWaiting := syncTimer.After(syncInterval)
		log.WithField("syncInterval", syncInterval.String()).Debug("Starting new iteration of background sync")
		m.singleBackgroundLoop(syncInterval)
		log.WithField("syncInterval", syncInterval.String()).Debug("Finished iteration of background sync")

		select {
		case <-m.closeChan:
			return
		// This handles cases when we didn't fetch nodes yet (e.g. on bootstrap)
		// but also case when we have 1 node, in which case rate.Limiter doesn't
		// throttle anything.
		case <-startWaiting:
		}
	}
}

func (m *Manager) singleBackgroundLoop(expectedLoopTime time.Duration) {
	// get a copy of the node identities to avoid locking the entire manager
	// throughout the process of running the datapath validation.
	nodes := m.GetNodeIdentities()
	limiter := rate.NewLimiter(
		rate.Limit(float64(len(nodes))/float64(expectedLoopTime.Seconds())),
		1, // One token in bucket to amortize for latency of the operation
	)
	for _, nodeIdentity := range nodes {
		if err := limiter.Wait(context.Background()); err != nil {
			log.WithError(err).Debug("Error while rate limiting backgroundSync updates")
		}
		select {
		case <-m.closeChan:
			return
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
		m.Iter(func(nh datapath.NodeHandler) {
			nh.NodeValidateImplementation(entry.node)
		})
		entry.mutex.Unlock()

		m.metricDatapathValidations.Inc()
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
	return true
}

// NodeUpdated is called after the information of a node has been updated. The
// node in the manager is added or updated if the source is allowed to update
// the node. If an update or addition has occurred, NodeUpdate() of the datapath
// interface is invoked.
func (m *Manager) NodeUpdated(n nodeTypes.Node) {
	log.WithFields(logrus.Fields{
		logfields.ClusterName: n.Cluster,
		logfields.NodeName:    n.Name,
	}).Info("Node updated")
	if log.Logger.IsLevelEnabled(logrus.DebugLevel) {
		log.WithField(logfields.Node, n.LogRepr()).Debugf("Received node update event from %s", n.Source)
	}

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
		if address.Type == addressing.NodeCiliumInternalIP || m.conf.NodeEncryptionEnabled() ||
			option.Config.EnableHostFirewall || option.Config.JoinCluster {
			tunnelIP = nodeIP
		}

		if m.conf.NodeIpsetNeeded() && address.Type == addressing.NodeInternalIP {
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
		if !m.conf.NodeEncryptionEnabled() {
			key = 0
		}

		var prefix netip.Prefix
		if v4 := address.IP.To4(); v4 != nil {
			prefix = ip.IPToNetPrefix(v4)
		} else {
			prefix = ip.IPToNetPrefix(address.IP.To16())
		}
		ipAddrStr := prefix.String()
		_, err := m.ipcache.Upsert(ipAddrStr, tunnelIP, key, nil, ipcache.Identity{
			ID:     remoteHostIdentity,
			Source: n.Source,
		})
		resource := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindNode, "", n.Name)
		m.upsertIntoIDMD(prefix, remoteHostIdentity, resource, n.Source)

		// Upsert() will return true if the ipcache entry is owned by
		// the source of the node update that triggered this node
		// update (kvstore, k8s, ...) The datapath is only updated if
		// that source of truth is updated.
		// The only exception are kube-apiserver entries. In that case,
		// we still want to inform subscribers about changes in auxiliary
		// data such as for example the health endpoint.
		overwriteErr := &ipcache.ErrOverwrite{
			ExistingSrc: source.KubeAPIServer,
			NewSrc:      n.Source,
		}
		if err != nil && !errors.Is(err, overwriteErr) {
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
		oldRID := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindNode, "", oldNode.Name)
		entry.node = n
		if dpUpdate {
			m.Iter(func(nh datapath.NodeHandler) {
				nh.NodeUpdate(oldNode, entry.node)
			})
		}
		// Delete the old node IP addresses if they have changed in this node.
		var oldNodeIPAddrs []string
		for _, address := range oldNode.IPAddresses {
			var prefix netip.Prefix
			if v4 := address.IP.To4(); v4 != nil {
				prefix = ip.IPToNetPrefix(v4)
			} else {
				prefix = ip.IPToNetPrefix(address.IP.To16())
			}
			if m.conf.NodeIpsetNeeded() && address.Type == addressing.NodeInternalIP &&
				!slices.Contains(ipsAdded, prefix.String()) {
				iptables.RemoveFromNodeIpset(address.IP)
			}
			if skipIPCache(address) {
				continue
			}
			oldNodeIPAddrs = append(oldNodeIPAddrs, prefix.String())
		}

		m.deleteIPCache(oldNode.Source, oldNodeIPAddrs, ipsAdded, remoteHostIdentity, oldRID)

		// Delete the old health IP addresses if they have changed in this node.
		oldHealthIPs := []string{}
		if oldNode.IPv4HealthIP != nil {
			oldHealthIPs = append(oldHealthIPs, oldNode.IPv4HealthIP.String())
		}
		if oldNode.IPv6HealthIP != nil {
			oldHealthIPs = append(oldHealthIPs, oldNode.IPv6HealthIP.String())
		}
		m.deleteIPCache(oldNode.Source, oldHealthIPs, healthIPsAdded, identity.IdentityUnknown, oldRID)

		// Delete the old ingress IP addresses if they have changed in this node.
		oldIngressIPs := []string{}
		if oldNode.IPv4IngressIP != nil {
			oldIngressIPs = append(oldIngressIPs, oldNode.IPv4IngressIP.String())
		}
		if oldNode.IPv6IngressIP != nil {
			oldIngressIPs = append(oldIngressIPs, oldNode.IPv6IngressIP.String())
		}
		m.deleteIPCache(oldNode.Source, oldIngressIPs, ingressIPsAdded, identity.IdentityUnknown, oldRID)

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
	m.persistNodesTrigger.TriggerWithReason("NodeUpdate")
}

// upsertIntoIDMD upserts the given CIDR into the ipcache.identityMetadata
// (IDMD) map. The given node identity determines which labels are associated
// with the CIDR.
func (m *Manager) upsertIntoIDMD(prefix netip.Prefix, id identity.NumericIdentity, rid ipcacheTypes.ResourceID, src source.Source) {
	if id == identity.ReservedIdentityHost {
		m.ipcache.UpsertLabels(prefix, labels.LabelHost, src, rid)
	} else {
		m.ipcache.UpsertLabels(prefix, labels.LabelRemoteNode, src, rid)
	}
}

func (m *Manager) removeFromIDMD(prefix netip.Prefix, id identity.NumericIdentity, rid ipcacheTypes.ResourceID) {
	if id == identity.ReservedIdentityHost {
		m.ipcache.RemoveLabels(prefix, labels.LabelHost, rid)
	} else {
		m.ipcache.RemoveLabels(prefix, labels.LabelRemoteNode, rid)
	}
}

// deleteIPCache deletes the IP addresses from the IPCache with the 'oldSource'
// if they are not found in the newIPs slice.
func (m *Manager) deleteIPCache(oldSource source.Source, oldIPs []string, newIPs []string, remoteID identity.NumericIdentity, rid ipcacheTypes.ResourceID) {
	for _, address := range oldIPs {
		var found bool
		for _, ipAdded := range newIPs {
			if ipAdded == address {
				found = true
				break
			}
		}
		// Delete from the IPCache if the node's IP addresses was not
		// added in this update.
		if !found {
			if remoteID != identity.IdentityUnknown {
				prefix, err := netip.ParsePrefix(address)
				if err != nil {
					log.WithError(err).WithField("prefix", address).Warn("Failed to parse prefix inside deleteIPCache")
				} else {
					m.removeFromIDMD(prefix, remoteID, rid)
				}
			}
			m.ipcache.Delete(address, oldSource)
		}
	}
}

// NodeDeleted is called after a node has been deleted. It removes the node
// from the manager if the node is still owned by the source of which the event
// origins from. If the node was removed, NodeDelete() is invoked of the
// datapath interface.
func (m *Manager) NodeDeleted(n nodeTypes.Node) {
	log.WithFields(logrus.Fields{
		logfields.ClusterName: n.Cluster,
		logfields.NodeName:    n.Name,
	}).Info("Node deleted")
	if log.Logger.IsLevelEnabled(logrus.DebugLevel) {
		log.Debugf("Received node delete event from %s", n.Source)
	}

	m.metricEventsReceived.WithLabelValues("delete", string(n.Source)).Inc()

	nodeIdentity := n.Identity()

	var (
		entry         *nodeEntry
		oldNodeExists bool
	)

	m.mutex.Lock()
	// If the node is restored from disk, it doesn't exist in the bookkeeping,
	// but we need to synthesize a deletion event for downstream.
	if n.Source == source.Restored {
		entry = &nodeEntry{
			node: n,
		}
	} else {
		entry, oldNodeExists = m.nodes[nodeIdentity]
		if !oldNodeExists {
			m.mutex.Unlock()
			return
		}
	}

	remoteHostIdentity := identity.ReservedIdentityHost
	if m.conf.RemoteNodeIdentitiesEnabled() {
		nid := identity.NumericIdentity(n.NodeIdentity)
		if nid != identity.IdentityUnknown && nid != identity.ReservedIdentityHost {
			remoteHostIdentity = nid
		} else if !n.IsLocal() {
			remoteHostIdentity = identity.ReservedIdentityRemoteNode
		}
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
		if m.conf.NodeIpsetNeeded() && address.Type == addressing.NodeInternalIP {
			iptables.RemoveFromNodeIpset(address.IP)
		}

		if m.legacyNodeIpBehavior() && address.Type != addressing.NodeCiliumInternalIP {
			continue
		}

		var prefix netip.Prefix
		if v4 := address.IP.To4(); v4 != nil {
			prefix = ip.IPToNetPrefix(v4)
		} else {
			prefix = ip.IPToNetPrefix(address.IP.To16())
		}
		rid := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindNode, "", n.Name)
		m.removeFromIDMD(prefix, remoteHostIdentity, rid)
		m.ipcache.Delete(prefix.String(), n.Source)
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
	processNodeDeletion(n.Cluster, n.Name)

	entry.mutex.Lock()
	delete(m.nodes, nodeIdentity)
	m.persistNodesTrigger.TriggerWithReason("NodeDeleted")
	m.mutex.Unlock()
	m.Iter(func(nh datapath.NodeHandler) {
		nh.NodeDelete(n)
	})
	entry.mutex.Unlock()
}

func processNodeDeletion(clusterName, nodeName string) {
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
func (m *Manager) StartNeighborRefresh(nh datapath.NodeNeighbors) {
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
