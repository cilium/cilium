// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Package nodes resolves endpoint addresses to immutable node-label snapshots.
package nodes

import (
	"net"
	"net/netip"
	"slices"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type nodeSnapshot struct {
	clusterID uint32
	labels    []string
	addresses []netip.Addr
}

// Resolver maintains an exact, cluster-aware reverse index of node-owned
// addresses. The notifier is retained for explicit lifecycle ownership;
// creating a Resolver deliberately has no subscription side effect.
type Resolver struct {
	ipcache     *ipcache.IPCache
	clusterInfo cmtypes.ClusterInfo
	notifier    manager.NodeStateNotifier

	mu         lock.RWMutex
	byIdentity map[nodeTypes.Identity]nodeSnapshot
	byAddress  map[netip.Addr]map[nodeTypes.Identity]struct{}
}

var _ getters.NodeLabelsGetter = (*Resolver)(nil)
var _ manager.NodeStateObserver = (*Resolver)(nil)

// NewResolver constructs an inert resolver. Subscription is explicit and is
// not performed during construction.
func NewResolver(ipc *ipcache.IPCache, clusterInfo cmtypes.ClusterInfo, notifier manager.NodeStateNotifier) *Resolver {
	return &Resolver{
		ipcache:     ipc,
		clusterInfo: clusterInfo,
		notifier:    notifier,
		byIdentity:  make(map[nodeTypes.Identity]nodeSnapshot),
		byAddress:   make(map[netip.Addr]map[nodeTypes.Identity]struct{}),
	}
}

// NodeUpsert atomically replaces the complete immutable snapshot for a node.
// Even an excluded update removes the node's previously accepted state.
func (r *Resolver) NodeUpsert(n nodeTypes.Node) {
	identity := nodeTypes.Identity{Name: n.Name, Cluster: n.Cluster}
	clusterID, accepted := r.classifyOwner(n)
	var snapshot nodeSnapshot
	if accepted {
		snapshot = nodeSnapshot{
			clusterID: clusterID,
			labels:    sortedLabels(n.Labels),
			addresses: nodeAddresses(n),
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.removeIdentityLocked(identity)
	if !accepted {
		return
	}

	r.byIdentity[identity] = snapshot
	for _, address := range snapshot.addresses {
		owners := r.byAddress[address]
		if owners == nil {
			owners = make(map[nodeTypes.Identity]struct{})
			r.byAddress[address] = owners
		}
		owners[identity] = struct{}{}
	}
}

// NodeDelete removes addresses from the stored snapshot, never from the
// potentially stale or incomplete delete payload.
func (r *Resolver) NodeDelete(n nodeTypes.Node) {
	identity := nodeTypes.Identity{Name: n.Name, Cluster: n.Cluster}
	r.mu.Lock()
	r.removeIdentityLocked(identity)
	r.mu.Unlock()
}

func (r *Resolver) removeIdentityLocked(identity nodeTypes.Identity) {
	old, exists := r.byIdentity[identity]
	if !exists {
		return
	}
	for _, address := range old.addresses {
		owners := r.byAddress[address]
		delete(owners, identity)
		if len(owners) == 0 {
			delete(r.byAddress, address)
		}
	}
	delete(r.byIdentity, identity)
}

func (r *Resolver) classifyOwner(n nodeTypes.Node) (uint32, bool) {
	if n.Cluster == r.clusterInfo.Name {
		if n.ClusterID == 0 || n.ClusterID == r.clusterInfo.ID {
			return r.clusterInfo.ID, true
		}
		return 0, false
	}

	if n.Cluster == "" || n.ClusterID == 0 || n.ClusterID == r.clusterInfo.ID {
		return 0, false
	}
	return n.ClusterID, true
}

func sortedLabels(source map[string]string) []string {
	labels := make([]string, 0, len(source))
	for key, value := range source {
		labels = append(labels, key+"="+value)
	}
	slices.Sort(labels)
	return labels
}

func nodeAddresses(n nodeTypes.Node) []netip.Addr {
	addresses := make([]netip.Addr, 0, len(n.IPAddresses)+4)
	seen := make(map[netip.Addr]struct{}, len(n.IPAddresses)+4)
	appendAddress := func(address netip.Addr) {
		if !address.IsValid() {
			return
		}
		address = address.Unmap()
		if _, exists := seen[address]; exists {
			return
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	appendIP := func(ip net.IP) {
		address, ok := netip.AddrFromSlice(ip)
		if ok {
			appendAddress(address)
		}
	}

	for _, address := range n.IPAddresses {
		appendIP(address.IP)
	}
	appendAddress(n.IPv4HealthIP.Addr)
	appendAddress(n.IPv6HealthIP.Addr)
	appendIP(n.IPv4IngressIP)
	appendIP(n.IPv6IngressIP)
	return addresses
}

// GetNodeLabels resolves only from event-established cluster provenance.
// Endpoint cluster names and userspace-filled identities are intentionally not
// inputs because neither is trustworthy when ClusterMesh address space overlaps.
func (r *Resolver) GetNodeLabels(ip netip.Addr, hint getters.NodeClusterHint) []string {
	if !ip.IsValid() {
		return nil
	}
	ip = ip.Unmap()

	ipcacheScope, expectedCluster, ok := r.resolveScope(hint)
	if !ok {
		return nil
	}

	if r.ipcache == nil {
		return nil
	}
	hostIP, found := r.ipcache.GetHostIP(cmtypes.AddrClusterFrom(ip, ipcacheScope))
	if found {
		return r.labelsForAddress(hostIP, expectedCluster)
	}

	// Direct-node fallback is permitted only after an exact scoped IPCache miss
	// and retains the already authenticated expected ClusterID.
	return r.labelsForAddress(ip, expectedCluster)
}

func (r *Resolver) resolveScope(hint getters.NodeClusterHint) (ipcacheScope, expectedCluster uint32, ok bool) {
	if hint.LocalEndpoint {
		if !hint.IdentityKnown || hint.Identity == identity.IdentityUnknown || isLocalOnlyReserved(hint.Identity) {
			return 0, r.clusterInfo.ID, true
		}
		clusterID, allocated := allocatedClusterID(hint.Identity)
		if allocated && clusterID == r.clusterInfo.ID {
			return 0, r.clusterInfo.ID, true
		}
		return 0, 0, false
	}

	if !hint.IdentityKnown {
		return 0, 0, false
	}
	if hint.Identity == identity.ReservedIdentityHost {
		return 0, r.clusterInfo.ID, true
	}

	clusterID, allocated := allocatedClusterID(hint.Identity)
	if !allocated {
		return 0, 0, false
	}
	if clusterID == r.clusterInfo.ID {
		return 0, r.clusterInfo.ID, true
	}
	if clusterID == 0 {
		return 0, 0, false
	}
	return clusterID, clusterID, true
}

func isLocalOnlyReserved(id identity.NumericIdentity) bool {
	switch id {
	case identity.ReservedIdentityHost, identity.ReservedIdentityHealth, identity.ReservedIdentityIngress:
		return true
	default:
		return false
	}
}

// allocatedClusterID validates the allocation scope and authoritative numeric
// bounds before interpreting the identity's embedded ClusterID.
func allocatedClusterID(id identity.NumericIdentity) (uint32, bool) {
	if id.HasLocalScope() || id.HasRemoteNodeScope() || id.Scope() != identity.IdentityScopeGlobal ||
		id.IsReservedIdentity() || identity.IsUserReservedIdentity(id) {
		return 0, false
	}

	clusterID := id.ClusterID()
	if id < identity.GetMinimalAllocationIdentity(clusterID) || id > identity.GetMaximumAllocationIdentity(clusterID) {
		return 0, false
	}
	return clusterID, true
}

func (r *Resolver) labelsForAddress(address netip.Addr, expectedCluster uint32) []string {
	if !address.IsValid() {
		return nil
	}
	address = address.Unmap()

	r.mu.RLock()
	defer r.mu.RUnlock()

	var labels []string
	matches := 0
	for identity := range r.byAddress[address] {
		snapshot, exists := r.byIdentity[identity]
		if !exists || snapshot.clusterID != expectedCluster {
			continue
		}
		matches++
		if matches > 1 {
			return nil
		}
		labels = snapshot.labels
	}
	if matches != 1 {
		return nil
	}
	return labels
}
