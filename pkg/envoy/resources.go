// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"

	envoyAPI "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/identity"
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

	// HttpConnectionManagerTypeURL is the type URL of HttpConnectionManager filter.
	HttpConnectionManagerTypeURL = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"

	// TCPProxyTypeURL is the type URL of TCPProxy filter.
	TCPProxyTypeURL = "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy"

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

	ipcache IPCacheEventSource
}

type IPCacheEventSource interface {
	AddListener(ipcache.IPIdentityMappingListener)
}

func newNPHDSCache(ipcache IPCacheEventSource) NPHDSCache {
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
//
// Note that the caller is responsible for passing 'oldID' when 'cidrCluster' has been
// associated with a different ID before, as this function does not search for conflicting
// IP/ID mappings.
func (cache *NPHDSCache) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster,
	oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity,
	encryptKey uint8, nodeID uint16, k8sMeta *ipcache.K8sMetadata) {
	cidr := cidrCluster.AsIPNet()

	cidrStr := cidr.String()
	resourceName := newID.ID.StringID()

	scopedLog := log.WithFields(logrus.Fields{
		logfields.IPAddr:       cidrStr,
		logfields.Identity:     resourceName,
		logfields.Modification: modType,
	})

	// Look up the current resources for the specified Identity.
	msg, err := cache.Lookup(NetworkPolicyHostsTypeURL, resourceName)
	if err != nil {
		scopedLog.WithError(err).Warning("Can't lookup NPHDS cache")
		return
	}

	var npHost *envoyAPI.NetworkPolicyHosts
	if msg != nil {
		npHost = msg.(*envoyAPI.NetworkPolicyHosts)
	}

	switch modType {
	case ipcache.Upsert:
		// Delete ID to IP mapping before adding the new mapping,
		// but only if the old ID is different.
		if oldID != nil && oldID.ID != newID.ID {
			// Recursive call to delete the 'cidr' from the 'oldID'
			cache.OnIPIdentityCacheChange(ipcache.Delete, cidrCluster, nil, nil, nil, *oldID, encryptKey, nodeID, k8sMeta)
		}
		err := cache.handleIPUpsert(npHost, resourceName, cidrStr, newID.ID)
		if err != nil {
			scopedLog.WithError(err).Warning("NPHSD upsert failed")
		}
	case ipcache.Delete:
		err := cache.handleIPDelete(npHost, resourceName, cidrStr)
		if err != nil {
			scopedLog.WithError(err).Warning("NPHDS delete failed")
		}
	}
}

// handleIPUpsert adds elements to the NPHDS cache with the specified peer IP->ID mapping.
func (cache *NPHDSCache) handleIPUpsert(npHost *envoyAPI.NetworkPolicyHosts, identityStr, cidrStr string, newID identity.NumericIdentity) error {
	var hostAddresses []string
	if npHost == nil {
		hostAddresses = make([]string, 0, 1)
		hostAddresses = append(hostAddresses, cidrStr)
	} else {
		// Resource already exists, create a copy of it and insert
		// the new IP address into its HostAddresses list, if not already there.
		for _, addr := range npHost.HostAddresses {
			if addr == cidrStr {
				// IP already exists, nothing to add
				return nil
			}
		}
		hostAddresses = make([]string, 0, len(npHost.HostAddresses)+1)
		hostAddresses = append(hostAddresses, npHost.HostAddresses...)
		hostAddresses = append(hostAddresses, cidrStr)
		sort.Strings(hostAddresses)
	}

	newNpHost := envoyAPI.NetworkPolicyHosts{
		Policy:        uint64(newID),
		HostAddresses: hostAddresses,
	}
	if err := newNpHost.Validate(); err != nil {
		return fmt.Errorf("Could not validate NPHDS resource update on upsert: %s (%w)", newNpHost.String(), err)
	}
	_, updated, _ := cache.Upsert(NetworkPolicyHostsTypeURL, identityStr, &newNpHost)
	if !updated {
		return fmt.Errorf("NPHDS cache not updated when expected adding: %s", newNpHost.String())
	}
	return nil
}

// handleIPUpsert deletes elements from the NPHDS cache with the specified peer IP->ID mapping.
func (cache *NPHDSCache) handleIPDelete(npHost *envoyAPI.NetworkPolicyHosts, identityStr, cidrStr string) error {
	if npHost == nil {
		// Doesn't exist; already deleted.
		return nil
	}

	targetIndex := -1

	for i, endpointIP := range npHost.HostAddresses {
		if endpointIP == cidrStr {
			targetIndex = i
			break
		}
	}
	if targetIndex < 0 {
		return errors.New("Can't find IP in NPHDS cache")
	}

	// If removing this host would result in empty list, delete it.
	// Otherwise, update to a list that doesn't contain the target IP
	if len(npHost.HostAddresses) <= 1 {
		cache.Delete(NetworkPolicyHostsTypeURL, identityStr)
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
			return fmt.Errorf("Could not validate NPHDS resource update on delete: %s (%w)", newNpHost.String(), err)
		}
		_, updated, _ := cache.Upsert(NetworkPolicyHostsTypeURL, identityStr, &newNpHost)
		if !updated {
			return fmt.Errorf("NPHDS cache not updated when expected deleting: %s", newNpHost.String())
		}
	}
	return nil
}
