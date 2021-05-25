// Copyright 2019 Authors of Hubble
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

package getters

import (
	"net"

	"k8s.io/client-go/tools/cache"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
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
	GetIdentity(id uint32) (*models.Identity, error)
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
	GetServiceByAddr(ip net.IP, port uint16) (service flowpb.Service, ok bool)
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
