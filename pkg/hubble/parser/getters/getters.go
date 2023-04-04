// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package getters

import (
	"net/netip"

	"k8s.io/client-go/tools/cache"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	cgroupManager "github.com/cilium/cilium/pkg/cgroups/manager"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
)

// DNSGetter ...
type DNSGetter interface {
	// GetNamesOf fetches FQDNs of a given IP from the perspective of
	// the endpoint with ID sourceEpID. The returned names must not have
	// trailing dots.
	GetNamesOf(sourceEpID uint32, ip netip.Addr) (names []string)
}

// EndpointGetter ...
type EndpointGetter interface {
	// GetEndpointInfo looks up endpoint by IP address.
	GetEndpointInfo(ip netip.Addr) (endpoint v1.EndpointInfo, ok bool)
	// GetEndpointInfo looks up endpoint by id
	GetEndpointInfoByID(id uint16) (endpoint v1.EndpointInfo, ok bool)
}

// IdentityGetter ...
type IdentityGetter interface {
	// GetIdentity fetches a full identity object given a numeric security id.
	GetIdentity(id uint32) (*identity.Identity, error)
}

// IPGetter fetches per-IP metadata
type IPGetter interface {
	// GetK8sMetadata returns Kubernetes metadata for the given IP address.
	GetK8sMetadata(ip netip.Addr) *ipcache.K8sMetadata
	// LookupSecIDByIP returns the corresponding security identity that
	// endpoint IP maps to as well as if the corresponding entry exists.
	LookupSecIDByIP(ip netip.Addr) (ipcache.Identity, bool)
}

// ServiceGetter fetches service metadata.
type ServiceGetter interface {
	GetServiceByAddr(ip netip.Addr, port uint16) *flowpb.Service
}

// StoreGetter ...
type StoreGetter interface {
	// GetK8sStore return the k8s watcher cache store for the given resource name.
	// Currently only resource networkpolicy and namespace are supported.
	// WARNING: the objects returned by these stores can't be used to create
	// update objects into k8s as well as the objects returned by these stores
	// should only be used for reading.
	GetK8sStore(name string) cache.Store
}

// LinkGetter fetches local link information.
type LinkGetter interface {
	// GetIfNameCached returns the name of an interface (if it exists) by
	// looking it up in a regularly updated cache
	GetIfNameCached(ifIndex int) (string, bool)

	// Name returns the name of an interface, or returns a string
	// containing the ifindex if the link name cannot be determined.
	Name(ifIndex uint32) string
}

// PodMetadataGetter returns pod metadata based on identifiers received from
// datapath trace events.
type PodMetadataGetter interface {
	// GetPodMetadataForContainer returns the pod metadata for the given container
	// cgroup id.
	GetPodMetadataForContainer(cgroupId uint64) *cgroupManager.PodMetadata
}
