// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"net"
	"sort"
	"sync"

	envoyAPI "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// ListenerTypeURL is the type URL of Listener resources.
	ListenerTypeURL = "type.googleapis.com/envoy.config.listener.v3.Listener"

	// RouteTypeURL is the type URL of HTTP Route resources.
	RouteTypeURL = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration"

	// ClusterTypeURL is the type URL of Cluster resources.
	ClusterTypeURL = "type.googleapis.com/envoy.config.cluster.v3.Cluster"

	// HttpConnectionManagerTypeURL is the type URL of HttpConnectionManager resources.
	HttpConnectionManagerTypeURL = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"

	// EndpointTypeURL is the type URL of Endpoint resources.
	EndpointTypeURL = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment"

	// SecretTypeURL is the type URL of Endpoint resources.
	SecretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

	// NetworkPolicyTypeURL is the type URL of NetworkPolicy resources.
	NetworkPolicyTypeURL = "type.googleapis.com/cilium.NetworkPolicy"

	// NetworkPolicyHostsTypeURL is the type URL of NetworkPolicyHosts resources.
	NetworkPolicyHostsTypeURL = "type.googleapis.com/cilium.NetworkPolicyHosts"

	// DownstreamTlsContextURL is the type URL of DownstreamTlsContext
	DownstreamTlsContextURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext"
)

// NPHDSCache is a cache of resources in the Network Policy Hosts Discovery
// Service.
//
// NetworkPolicyHostsCache is the global cache of resources of type
// NetworkPolicyHosts. Resources in this cache must have the
// NetworkPolicyHostsTypeURL type URL.
type NPHDSCache struct {
	*xds.Cache

	ipcache *ipcache.IPCache
}

func newNPHDSCache(ipcache *ipcache.IPCache) NPHDSCache {
	return NPHDSCache{Cache: xds.NewCache(), ipcache: ipcache}
}

var (
	observerOnce = sync.Once{}
)

// HandleResourceVersionAck is required to implement ResourceVersionAckObserver.
// We use this to start the IP Cache listener on the first ACK so that we only
// start the IP Cache listener if there is an Envoy node that uses NPHDS (e.g.,
// Istio node, or host proxy running on kernel w/o LPM bpf map support).
func (cache *NPHDSCache) HandleResourceVersionAck(ackVersion uint64, nackVersion uint64, nodeIP string, resourceNames []string, typeURL string, detail string) {
	// Start caching for IP/ID mappings on the first indication someone wants them
	observerOnce.Do(func() {
		cache.ipcache.AddListener(cache)
	})
}

// OnIPIdentityCacheGC is required to implement IPIdentityMappingListener.
func (cache *NPHDSCache) OnIPIdentityCacheGC() {
	// We don't have anything to synchronize in this case.
}

// OnIPIdentityCacheChange pushes modifications to the IP<->Identity mapping
// into the Network Policy Host Discovery Service (NPHDS).
func (cache *NPHDSCache) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr net.IPNet,
	oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity,
	encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
	// An upsert where an existing pair exists should translate into a
	// delete (for the old Identity) followed by an upsert (for the new).
	if oldID != nil && modType == ipcache.Upsert {
		// Skip update if identity is identical
		if oldID.ID == newID.ID {
			return
		}

		cache.OnIPIdentityCacheChange(ipcache.Delete, cidr, nil, nil, nil, *oldID, encryptKey, k8sMeta)
	}

	cidrStr := cidr.String()

	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr:       cidrStr,
		logfields.Identity:     newID,
		logfields.Modification: modType,
	})

	// Look up the current resources for the specified Identity.
	resourceName := newID.ID.StringID()
	msg, err := cache.Lookup(NetworkPolicyHostsTypeURL, resourceName)
	if err != nil {
		scopedLog.WithError(err).Warning("Can't lookup NPHDS cache")
		return
	}

	switch modType {
	case ipcache.Upsert:
		var hostAddresses []string
		if msg == nil {
			hostAddresses = make([]string, 0, 1)
		} else {
			// If the resource already exists, create a copy of it and insert
			// the new IP address into its HostAddresses list.
			npHost := msg.(*envoyAPI.NetworkPolicyHosts)
			hostAddresses = make([]string, 0, len(npHost.HostAddresses)+1)
			hostAddresses = append(hostAddresses, npHost.HostAddresses...)
		}
		hostAddresses = append(hostAddresses, cidrStr)
		sort.Strings(hostAddresses)

		newNpHost := envoyAPI.NetworkPolicyHosts{
			Policy:        uint64(newID.ID),
			HostAddresses: hostAddresses,
		}
		if err := newNpHost.Validate(); err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				logfields.XDSResource: newNpHost.String(),
			}).Warning("Could not validate NPHDS resource update on upsert")
			return
		}
		cache.Upsert(NetworkPolicyHostsTypeURL, resourceName, &newNpHost)
	case ipcache.Delete:
		if msg == nil {
			// Doesn't exist; already deleted.
			return
		}
		cache.handleIPDelete(msg.(*envoyAPI.NetworkPolicyHosts), resourceName, cidrStr)
	}
}

// handleIPUpsert deletes elements from the NPHDS cache with the specified peer IP->ID mapping.
func (cache *NPHDSCache) handleIPDelete(npHost *envoyAPI.NetworkPolicyHosts, peerIdentity, peerIP string) {
	targetIndex := -1

	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr:       peerIP,
		logfields.Identity:     peerIdentity,
		logfields.Modification: ipcache.Delete,
	})
	for i, endpointIP := range npHost.HostAddresses {
		if endpointIP == peerIP {
			targetIndex = i
			break
		}
	}
	if targetIndex < 0 {
		scopedLog.Warning("Can't find IP in NPHDS cache")
		return
	}

	// If removing this host would result in empty list, delete it.
	// Otherwise, update to a list that doesn't contain the target IP
	if len(npHost.HostAddresses) <= 1 {
		cache.Delete(NetworkPolicyHostsTypeURL, peerIdentity)
	} else {
		// If the resource is to be updated, create a copy of it before
		// removing the IP address from its HostAddresses list.
		hostAddresses := make([]string, 0, len(npHost.HostAddresses)-1)
		if len(npHost.HostAddresses) == targetIndex {
			hostAddresses = append(hostAddresses, npHost.HostAddresses[0:targetIndex]...)
		} else {
			hostAddresses = append(hostAddresses, npHost.HostAddresses[0:targetIndex]...)
			hostAddresses = append(hostAddresses, npHost.HostAddresses[targetIndex+1:]...)
		}

		newNpHost := envoyAPI.NetworkPolicyHosts{
			Policy:        uint64(npHost.Policy),
			HostAddresses: hostAddresses,
		}
		if err := newNpHost.Validate(); err != nil {
			scopedLog.WithError(err).Warning("Could not validate NPHDS resource update on delete")
			return
		}
		cache.Upsert(NetworkPolicyHostsTypeURL, peerIdentity, &newNpHost)
	}
}
