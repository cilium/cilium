// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/exp/slices"

	"github.com/cilium/workerpool"

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
	"github.com/cilium/cilium/pkg/set"
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
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (bool, error)
	Delete(IP string, source source.Source) bool
	UpsertLabels(prefix netip.Prefix, lbls labels.Labels, src source.Source, rid ipcacheTypes.ResourceID)
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

// NodeUpdated is called after the information of a node has been updated. The
// node in the manager is added or updated if the source is allowed to update
// the node. If an update or addition has occurred, NodeUpdate() of the datapath
// interface is invoked.
func (m *manager) NodeUpdated(n nodeTypes.Node) {
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
		if (!m.conf.NodeEncryptionEnabled() &&
			(address.Type == addressing.NodeExternalIP || address.Type == addressing.NodeInternalIP)) ||
			// Also ignore any remote node's key if the local node opted to not perform
			// node-to-node encryption
			node.GetOptOutNodeEncryption() {
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
		m.upsertIntoIDMD(prefix, remoteHostIdentity, resource)

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
		entry.node = n
		if dpUpdate {
			m.Iter(func(nh datapath.NodeHandler) {
				nh.NodeUpdate(oldNode, entry.node)
			})
		}
		// Delete the old node IP addresses if they have changed in this node.
		var oldNodeIPAddrs []string
		for _, address := range oldNode.IPAddresses {
			if option.Config.NodeIpsetNeeded() && address.Type == addressing.NodeInternalIP &&
				!slices.Contains(ipsAdded, address.IP.String()) {
				iptables.RemoveFromNodeIpset(address.IP)
			}
			if skipIPCache(address) {
				continue
			}
			var prefix netip.Prefix
			if v4 := address.IP.To4(); v4 != nil {
				prefix = ip.IPToNetPrefix(v4)
			} else {
				prefix = ip.IPToNetPrefix(address.IP.To16())
			}
			oldNodeIPAddrs = append(oldNodeIPAddrs, prefix.String())
		}
		m.deleteIPCache(oldNode.Source, oldNodeIPAddrs, ipsAdded)

		// Delete the old health IP addresses if they have changed in this node.
		oldHealthIPs := []string{}
		if oldNode.IPv4HealthIP != nil {
			oldHealthIPs = append(oldHealthIPs, oldNode.IPv4HealthIP.String())
		}
		if oldNode.IPv6HealthIP != nil {
			oldHealthIPs = append(oldHealthIPs, oldNode.IPv6HealthIP.String())
		}
		m.deleteIPCache(oldNode.Source, oldHealthIPs, healthIPsAdded)

		// Delete the old ingress IP addresses if they have changed in this node.
		oldIngressIPs := []string{}
		if oldNode.IPv4IngressIP != nil {
			oldIngressIPs = append(oldIngressIPs, oldNode.IPv4IngressIP.String())
		}
		if oldNode.IPv6IngressIP != nil {
			oldIngressIPs = append(oldIngressIPs, oldNode.IPv6IngressIP.String())
		}
		m.deleteIPCache(oldNode.Source, oldIngressIPs, ingressIPsAdded)

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
}

// upsertIntoIDMD upserts the given CIDR into the ipcache.identityMetadata
// (IDMD) map. The given node identity determines which labels are associated
// with the CIDR.
func (m *manager) upsertIntoIDMD(prefix netip.Prefix, id identity.NumericIdentity, rid ipcacheTypes.ResourceID) {
	if id == identity.ReservedIdentityHost {
		m.ipcache.UpsertLabels(prefix, labels.LabelHost, source.Local, rid)
	} else {
		m.ipcache.UpsertLabels(prefix, labels.LabelRemoteNode, source.CustomResource, rid)
	}
}

// deleteIPCache deletes the IP addresses from the IPCache with the 'oldSource'
// if they are not found in the newIPs slice.
func (m *manager) deleteIPCache(oldSource source.Source, oldIPs []string, newIPs []string) {
	_, diff := set.SliceSubsetOf(oldIPs, newIPs)
	for _, address := range diff {
		m.ipcache.Delete(address, oldSource)
	}
}

// NodeDeleted is called after a node has been deleted. It removes the node
// from the manager if the node is still owned by the source of which the event
// origins from. If the node was removed, NodeDelete() is invoked of the
// datapath interface.
func (m *manager) NodeDeleted(n nodeTypes.Node) {
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
			m.Stop(context.Background())
		} else {
			log.Debugf("Ignoring delete event of node %s from source %s. The node is owned by %s",
				n.Name, n.Source, entry.node.Source)
		}
		return
	}

	extraIPs := []net.IP{
		entry.node.IPv4HealthIP, entry.node.IPv6HealthIP,
		entry.node.IPv4IngressIP, entry.node.IPv6IngressIP,
	}
	toDelete := make([]string, 0, len(entry.node.IPAddresses)+len(extraIPs))
	for _, address := range entry.node.IPAddresses {
		if option.Config.NodeIpsetNeeded() && address.Type == addressing.NodeInternalIP {
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
		toDelete = append(toDelete, prefix.String())
	}
	for _, address := range extraIPs {
		if address != nil {
			toDelete = append(toDelete, address.String())
		}
	}
	m.deleteIPCache(n.Source, toDelete, nil)

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
func (m *manager) StartNeighborRefresh(nh datapath.NodeHandler) {
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
