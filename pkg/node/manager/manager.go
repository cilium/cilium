// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/cilium/workerpool"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/source"
)

var (
	randGen                    = rand.NewSafeRand(time.Now().UnixNano())
	baseBackgroundSyncInterval = time.Minute
)

const (
	numBackgroundWorkers = 1
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
	GetMetadataByPrefix(prefix netip.Prefix) ipcache.PrefixInfo
	UpsertMetadata(prefix netip.Prefix, src source.Source, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata)
	OverrideIdentity(prefix netip.Prefix, identityLabels labels.Labels, src source.Source, resource ipcacheTypes.ResourceID)
	RemoveMetadata(prefix netip.Prefix, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata)
	RemoveIdentityOverride(prefix netip.Prefix, identityLabels labels.Labels, resource ipcacheTypes.ResourceID)
}

// Configuration is the set of configuration options the node manager depends
// on
type Configuration interface {
	TunnelingEnabled() bool
	RemoteNodeIdentitiesEnabled() bool
	NodeEncryptionEnabled() bool
	EncryptionEnabled() bool
}

var _ Notifier = (*manager)(nil)

// manager is the entity that manages a collection of nodes
type manager struct {
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

	// workerpool manages background workers
	workerpool *workerpool.WorkerPool

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
}

// Subscribe subscribes the given node handler to node events.
func (m *manager) Subscribe(nh datapath.NodeHandler) {
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
func (m *manager) Unsubscribe(nh datapath.NodeHandler) {
	m.nodeHandlersMu.Lock()
	delete(m.nodeHandlers, nh)
	m.nodeHandlersMu.Unlock()
}

// Iter executes the given function in all subscribed node handlers.
func (m *manager) Iter(f func(nh datapath.NodeHandler)) {
	m.nodeHandlersMu.RLock()
	defer m.nodeHandlersMu.RUnlock()

	for nh := range m.nodeHandlers {
		f(nh)
	}
}

// New returns a new node manager
func New(name string, c Configuration, ipCache IPCache) (*manager, error) {
	m := &manager{
		name:              name,
		nodes:             map[nodeTypes.Identity]*nodeEntry{},
		conf:              c,
		controllerManager: controller.NewManager(),
		nodeHandlers:      map[datapath.NodeHandler]struct{}{},
		ipcache:           ipCache,
	}

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

	return m, nil
}

func (m *manager) Start(hive.HookContext) error {
	m.workerpool = workerpool.New(numBackgroundWorkers)
	return m.workerpool.Submit("backgroundSync", m.backgroundSync)
}

// Stop shuts down a node manager
func (m *manager) Stop(hive.HookContext) error {
	if m.workerpool != nil {
		if err := m.workerpool.Close(); err != nil {
			return err
		}
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	metrics.Unregister(m.metricNumNodes)
	metrics.Unregister(m.metricEventsReceived)
	metrics.Unregister(m.metricDatapathValidations)

	return nil
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
	m.mutex.RLock()
	numNodes := len(m.nodes)
	m.mutex.RUnlock()

	return backoff.ClusterSizeDependantInterval(baseInterval, numNodes)
}

func (m *manager) backgroundSyncInterval() time.Duration {
	return m.ClusterSizeDependantInterval(baseBackgroundSyncInterval)
}

// backgroundSync ensures that local node has a valid datapath in-place for
// each node in the cluster. See NodeValidateImplementation().
func (m *manager) backgroundSync(ctx context.Context) error {
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
		case <-ctx.Done():
			return nil
		case <-syncTimer.After(syncInterval):
		}
	}
}

// legacyNodeIpBehavior returns true if the agent is still running in legacy
// mode regarding node IPs
func (m *manager) legacyNodeIpBehavior() bool {
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
	// Needed to store the tunnel endpoint for pod->remote node in the
	// ipcache so that this traffic goes through the tunnel.
	if m.conf.EncryptionEnabled() && m.conf.TunnelingEnabled() {
		return false
	}
	return true
}

func (m *manager) nodeAddressHasTunnelIP(address nodeTypes.Address) bool {
	// If the host firewall is enabled, all traffic to remote nodes must go
	// through the tunnel to preserve the source identity as part of the
	// encapsulation. In encryption case we also want to use vxlan device
	// to create symmetric traffic when sending nodeIP->pod and pod->nodeIP.
	return address.Type == addressing.NodeCiliumInternalIP || m.conf.EncryptionEnabled() ||
		option.Config.EnableHostFirewall || option.Config.JoinCluster
}

func (m *manager) nodeAddressHasEncryptKey(address nodeTypes.Address) bool {
	// If we are doing encryption, but not node based encryption, then do not
	// add a key to the nodeIPs so that we avoid a trip through stack and attempting
	// to encrypt something we know does not have an encryption policy installed
	// in the datapath. By setting key=0 and tunnelIP this will result in traffic
	// being sent unencrypted over overlay device.
	return m.conf.NodeEncryptionEnabled() &&
		// Also ignore any remote node's key if the local node opted to not perform
		// node-to-node encryption
		!node.GetOptOutNodeEncryption()
}

func (m *manager) nodeAddressSkipsIPCache(address nodeTypes.Address) bool {
	return m.legacyNodeIpBehavior() && address.Type != addressing.NodeCiliumInternalIP
}

func (m *manager) nodeIdentityLabels(n nodeTypes.Node) (nodeLabels labels.Labels, hasOverride bool) {
	nodeLabels = labels.NewFrom(labels.LabelRemoteNode)
	if m.conf.RemoteNodeIdentitiesEnabled() {
		if n.IsLocal() {
			nodeLabels = labels.NewFrom(labels.LabelHost)
		} else if !identity.NumericIdentity(n.NodeIdentity).IsReservedIdentity() {
			// This needs to match clustermesh-apiserver's VMManager.AllocateNodeIdentity
			nodeLabels = labels.Map2Labels(n.Labels, labels.LabelSourceK8s)
			hasOverride = true
		}
	} else {
		nodeLabels = labels.NewFrom(labels.LabelHost)
	}
	return nodeLabels, hasOverride
}

// NodeUpdated is called after the information of a node has been updated. The
// node in the manager is added or updated if the source is allowed to update
// the node. If an update or addition has occurred, NodeUpdate() of the datapath
// interface is invoked.
func (m *manager) NodeUpdated(n nodeTypes.Node) {
	log.Debugf("Received node update event from %s: %#v", n.Source, n)

	nodeIdentifier := n.Identity()
	dpUpdate := true
	var nodeIP netip.Addr
	if nIP := n.GetNodeIP(false); nIP != nil {
		// GH-24829: Support IPv6-only nodes.

		// Skip returning the error here because at this level, we assume that
		// the IP is valid as long as it's coming from nodeTypes.Node. This
		// object is created either from the node discovery (K8s) or from an
		// event from the kvstore.
		nodeIP, _ = ip.AddrFromIP(nIP)
	}

	resource := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindNode, "", n.Name)
	nodeLabels, nodeIdentityOverride := m.nodeIdentityLabels(n)

	var nodeIPsAdded, healthIPsAdded, ingressIPsAdded []netip.Prefix

	for _, address := range n.IPAddresses {
		if option.Config.NodeIpsetNeeded() && address.Type == addressing.NodeInternalIP {
			iptables.AddToNodeIpset(address.IP)
		}

		if m.nodeAddressSkipsIPCache(address) {
			continue
		}

		var tunnelIP netip.Addr
		if m.nodeAddressHasTunnelIP(address) {
			tunnelIP = nodeIP
		}

		var key uint8
		if m.nodeAddressHasEncryptKey(address) {
			key = n.EncryptionKey
		}

		prefix := ip.IPToNetPrefix(address.IP)
		// We expect the node manager to have a source of either Kubernetes,
		// CustomResource, or KVStore. Prioritize the KVStore source over the
		// rest as it is the strongest source, i.e. only trigger datapath
		// updates if the information we receive takes priority.
		//
		// The only exception are kube-apiserver entries. In that case,
		// we still want to inform subscribers about changes in auxiliary
		// data such as for example the health endpoint.
		existing := m.ipcache.GetMetadataByPrefix(prefix).Source()
		overwrite := source.AllowOverwrite(existing, n.Source)
		if !overwrite && existing != source.KubeAPIServer {
			dpUpdate = false
		}

		// Always associate the prefix with metadata, even though this may not
		// end up in an ipcache entry.
		m.ipcache.UpsertMetadata(prefix, n.Source, resource,
			nodeLabels,
			ipcacheTypes.TunnelPeer{Addr: tunnelIP},
			ipcacheTypes.EncryptKey(key))
		if nodeIdentityOverride {
			m.ipcache.OverrideIdentity(prefix, nodeLabels, n.Source, resource)
		}
		nodeIPsAdded = append(nodeIPsAdded, prefix)
	}

	for _, address := range []net.IP{n.IPv4HealthIP, n.IPv6HealthIP} {
		healthIP := ip.IPToNetPrefix(address)
		if !healthIP.IsValid() {
			continue
		}
		if !source.AllowOverwrite(m.ipcache.GetMetadataByPrefix(healthIP).Source(), n.Source) {
			dpUpdate = false
		}

		m.ipcache.UpsertMetadata(healthIP, n.Source, resource,
			labels.LabelHealth,
			ipcacheTypes.TunnelPeer{Addr: nodeIP},
			ipcacheTypes.EncryptKey(n.EncryptionKey))
		healthIPsAdded = append(healthIPsAdded, healthIP)
	}

	for _, address := range []net.IP{n.IPv4IngressIP, n.IPv6IngressIP} {
		ingressIP := ip.IPToNetPrefix(address)
		if !ingressIP.IsValid() {
			continue
		}
		if !source.AllowOverwrite(m.ipcache.GetMetadataByPrefix(ingressIP).Source(), n.Source) {
			dpUpdate = false
		}

		m.ipcache.UpsertMetadata(ingressIP, n.Source, resource,
			labels.LabelIngress,
			ipcacheTypes.TunnelPeer{Addr: nodeIP},
			ipcacheTypes.EncryptKey(n.EncryptionKey))
		ingressIPsAdded = append(ingressIPsAdded, ingressIP)
	}

	m.mutex.Lock()
	entry, oldNodeExists := m.nodes[nodeIdentifier]
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

		m.removeNodeFromIPCache(oldNode, resource, nodeIPsAdded, healthIPsAdded, ingressIPsAdded)

		entry.mutex.Unlock()
	} else {
		m.metricEventsReceived.WithLabelValues("add", string(n.Source)).Inc()
		m.metricNumNodes.Inc()

		entry = &nodeEntry{node: n}
		entry.mutex.Lock()
		m.nodes[nodeIdentifier] = entry
		m.mutex.Unlock()
		if dpUpdate {
			m.Iter(func(nh datapath.NodeHandler) {
				nh.NodeAdd(entry.node)
			})
		}
		entry.mutex.Unlock()
	}
}

// removeNodeFromIPCache removes all addresses associated with oldNode from the IPCache,
// unless they are present in the nodeIPsAdded, healthIPsAdded, ingressIPsAdded lists.
//
// The removal logic in this function should mirror the upsert logic in NodeUpdated.
func (m *manager) removeNodeFromIPCache(oldNode nodeTypes.Node, resource ipcacheTypes.ResourceID,
	nodeIPsAdded, healthIPsAdded, ingressIPsAdded []netip.Prefix) {

	var oldNodeIP netip.Addr
	if nIP := oldNode.GetNodeIP(false); nIP != nil {
		// See comment in NodeUpdated().
		oldNodeIP, _ = ip.AddrFromIP(nIP)
	}
	oldNodeLabels, oldNodeIdentityOverride := m.nodeIdentityLabels(oldNode)

	// Delete the old node IP addresses if they have changed in this node.
	for _, address := range oldNode.IPAddresses {
		oldPrefix := ip.IPToNetPrefix(address.IP)
		if slices.Contains(nodeIPsAdded, oldPrefix) {
			continue
		}

		if option.Config.NodeIpsetNeeded() && address.Type == addressing.NodeInternalIP {
			iptables.RemoveFromNodeIpset(address.IP)
		}

		if m.nodeAddressSkipsIPCache(address) {
			continue
		}

		var oldTunnelIP netip.Addr
		if m.nodeAddressHasTunnelIP(address) {
			oldTunnelIP = oldNodeIP
		}

		var oldKey uint8
		if m.nodeAddressHasEncryptKey(address) {
			oldKey = oldNode.EncryptionKey
		}

		m.ipcache.RemoveMetadata(oldPrefix, resource,
			oldNodeLabels,
			ipcacheTypes.TunnelPeer{Addr: oldTunnelIP},
			ipcacheTypes.EncryptKey(oldKey))
		if oldNodeIdentityOverride {
			m.ipcache.RemoveIdentityOverride(oldPrefix, oldNodeLabels, resource)
		}
	}

	// Delete the old health IP addresses if they have changed in this node.
	for _, address := range []net.IP{oldNode.IPv4HealthIP, oldNode.IPv6HealthIP} {
		healthIP := ip.IPToNetPrefix(address)
		if !healthIP.IsValid() || slices.Contains(healthIPsAdded, healthIP) {
			continue
		}

		m.ipcache.RemoveMetadata(healthIP, resource,
			labels.LabelHealth,
			ipcacheTypes.TunnelPeer{Addr: oldNodeIP},
			ipcacheTypes.EncryptKey(oldNode.EncryptionKey))
	}

	// Delete the old ingress IP addresses if they have changed in this node.
	for _, address := range []net.IP{oldNode.IPv4IngressIP, oldNode.IPv6IngressIP} {
		ingressIP := ip.IPToNetPrefix(address)
		if !ingressIP.IsValid() || slices.Contains(ingressIPsAdded, ingressIP) {
			continue
		}

		m.ipcache.RemoveMetadata(ingressIP, resource,
			labels.LabelIngress,
			ipcacheTypes.TunnelPeer{Addr: oldNodeIP},
			ipcacheTypes.EncryptKey(oldNode.EncryptionKey))
	}
}

// NodeDeleted is called after a node has been deleted. It removes the node
// from the manager if the node is still owned by the source of which the event
// origins from. If the node was removed, NodeDelete() is invoked of the
// datapath interface.
func (m *manager) NodeDeleted(n nodeTypes.Node) {
	m.metricEventsReceived.WithLabelValues("delete", string(n.Source)).Inc()

	log.Debugf("Received node delete event from %s", n.Source)

	nodeIdentifier := n.Identity()

	m.mutex.Lock()
	entry, oldNodeExists := m.nodes[nodeIdentifier]
	if !oldNodeExists {
		m.mutex.Unlock()
		return
	}

	resource := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindNode, "", n.Name)

	// If the source is Kubernetes and the node is the node we are running on
	// Kubernetes is giving us a hint it is about to delete our node. Close down
	// the agent gracefully in this case.
	if n.Source != entry.node.Source {
		m.mutex.Unlock()
		if n.IsLocal() && n.Source == source.Kubernetes {
			log.Debugf("Kubernetes is deleting local node, close manager")
			m.Stop(context.Background())
		} else {
			log.Debugf("Ignoring delete event of node %s from source %s. The node is owned by %s",
				n.Name, n.Source, entry.node.Source)
		}
		return
	}

	m.removeNodeFromIPCache(entry.node, resource, nil, nil, nil)

	m.metricNumNodes.Dec()

	entry.mutex.Lock()
	delete(m.nodes, nodeIdentifier)
	m.mutex.Unlock()
	m.Iter(func(nh datapath.NodeHandler) {
		nh.NodeDelete(n)
	})
	entry.mutex.Unlock()
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
func (m *manager) StartNeighborRefresh(nh datapath.NodeNeighbors) {
	ctx, cancel := context.WithCancel(context.Background())
	controller.NewManager().UpdateController("neighbor-table-refresh",
		controller.ControllerParams{
			DoFunc: func(controllerCtx context.Context) error {
				// Cancel previous goroutines from previous controller run
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
