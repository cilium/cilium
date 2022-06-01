// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package getters

import (
	"net"

	"k8s.io/client-go/tools/cache"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/policy"
)

// DNSGetter ...
type DNSGetter interface {
	// GetNamesOf fetches FQDNs of a given IP from the perspective of
	// the endpoint with ID sourceEpID. The returned names must not have
	// trailing dots.
	GetNamesOf(sourceEpID uint32, ip net.IP) (names []string)
}

// EndpointGetter ...
type EndpointGetter interface {
	// GetEndpointInfo looks up endpoint by IP address.
	GetEndpointInfo(ip net.IP) (endpoint v1.EndpointInfo, ok bool)
	// GetEndpointInfo looks up endpoint by id
	GetEndpointInfoByID(id uint16) (endpoint v1.EndpointInfo, ok bool)
}

type EndpointsGetter interface {
	// GetEndpoints returns a map of the current policy.Endpoint(s).
	GetEndpoints() map[policy.Endpoint]struct{}
}

// IdentityGetter ...
type IdentityGetter interface {
	// GetIdentity fetches a full identity object given a numeric security id.
	GetIdentity(id uint32) (*identity.Identity, error)
}

// IPGetter fetches per-IP metadata
type IPGetter interface {
	// GetK8sMetadata returns Kubernetes metadata for the given IP address.
	GetK8sMetadata(ip net.IP) *ipcache.K8sMetadata
	// LookupSecIDByIP returns the corresponding security identity that
	// endpoint IP maps to as well as if the corresponding entry exists.
	LookupSecIDByIP(ip net.IP) (ipcache.Identity, bool)
}

// ServiceGetter fetches service metadata.
type ServiceGetter interface {
	GetServiceByAddr(ip net.IP, port uint16) *flowpb.Service
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
