// Copyright 2020 Authors of Cilium
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

// Package hubble defines getter interfaces Hubble uses to access Cilium state, as
// well as a monitor listener that sends monitor events to Hubble server.
//
// The getter interfaces are defined in: https://github.com/cilium/hubble/blob/master/pkg/parser/getters/getters.go
package hubble

import (
	"context"
	"fmt"
	"net"

	hubbleProto "github.com/cilium/hubble/api/v1/flow"
	hubbleV1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleIPCache "github.com/cilium/hubble/pkg/ipcache"
	hubbleEndpoint "github.com/cilium/hubble/pkg/parser/endpoint"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service"
)

// LocalIdentityGetter implements IdentityGetter interface from Hubble.
//  - IdentityGetter: https://github.com/cilium/hubble/blob/04ab72591faca62a305ce0715108876167182e04/pkg/parser/getters/getters.go#L40
type LocalIdentityGetter struct {
	allocator *cache.CachingIdentityAllocator
}

// NewLocalIdentityGetter returns an initialized pointer to LocalIdentityGetter.
func NewLocalIdentityGetter(allocator *cache.CachingIdentityAllocator) *LocalIdentityGetter {
	return &LocalIdentityGetter{allocator: allocator}
}

// GetIdentity looks up identity by ID from Cilium's identity cache. Hubble uses the identity info
// to populate source and destination labels of flows.
func (getter *LocalIdentityGetter) GetIdentity(securityIdentity uint64) (*models.Identity, error) {
	ident := getter.allocator.LookupIdentityByID(context.Background(), identity.NumericIdentity(securityIdentity))
	if ident == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return ident.GetModel(), nil
}

// LocalEndpointDNSGetter implements DNSGetter and EndpointGetter interfaces from Hubble.
//  - EndpointGetter: https://github.com/cilium/hubble/blob/04ab72591faca62a305ce0715108876167182e04/pkg/parser/getters/getters.go#L34
//  - DNSGetter: https://github.com/cilium/hubble/blob/04ab72591faca62a305ce0715108876167182e04/pkg/parser/getters/getters.go#L27
type LocalEndpointDNSGetter struct {
	manager *endpointmanager.EndpointManager
}

// NewLocalEndpointDNSGetter returns an initialized pointer to LocalEndpointDNSGetter.
func NewLocalEndpointDNSGetter(manager *endpointmanager.EndpointManager) *LocalEndpointDNSGetter {
	return &LocalEndpointDNSGetter{manager: manager}
}

// GetEndpoint returns endpoint info for a given IP address. Hubble uses this function to populate
// fields like namespace and pod name for local endpoints.
func (getter *LocalEndpointDNSGetter) GetEndpoint(ip net.IP) (endpoint *hubbleV1.Endpoint, ok bool) {
	ep := getter.manager.LookupIP(ip)
	if ep == nil {
		return nil, false
	}
	return hubbleEndpoint.ParseEndpointFromModel(ep.GetModel()), true
}

// GetNamesOf implements DNSGetter.GetNamesOf. It looks up DNS names of a given IP from the
// FQDN cache of an endpoint specified by sourceEpID.
func (getter *LocalEndpointDNSGetter) GetNamesOf(sourceEpID uint64, ip net.IP) []string {
	ep := getter.manager.LookupCiliumID(uint16(sourceEpID))
	if ep == nil {
		return nil
	}
	return ep.DNSHistory.LookupIP(ip)
}

// LocalIPGetter implements IPGetter interface from Hubble.
//  - IPGetter: https://github.com/cilium/hubble/blob/04ab72591faca62a305ce0715108876167182e04/pkg/parser/getters/getters.go#L46
type LocalIPGetter struct {
	ipCache *ipcache.IPCache
}

// NewLocalIPGetter returns an initialized pointer to LocalIPGetter.
func NewLocalIPGetter(ipCache *ipcache.IPCache) *LocalIPGetter {
	return &LocalIPGetter{ipCache: ipCache}
}

// GetIPIdentity returns the IP identity of the given IP address. Hubble uses this function to populate
// fields like namespace and pod name for remote endpoints. If the K8s metadata is unavailable, it sets
// the Identity field for the IP identity.
func (getter *LocalIPGetter) GetIPIdentity(ip net.IP) (hubbleIPCache.IPIdentity, bool) {
	ipIdentity, ok := getter.ipCache.LookupByIP(ip.String())
	if !ok {
		return hubbleIPCache.IPIdentity{}, false
	}
	meta := getter.ipCache.GetK8sMetadata(ip.String())
	if meta == nil {
		return hubbleIPCache.IPIdentity{
			Identity: ipIdentity.ID,
		}, true
	}
	return hubbleIPCache.IPIdentity{
		Identity:  ipIdentity.ID,
		Namespace: meta.Namespace,
		PodName:   meta.PodName,
	}, true
}

// LocalServiceGetter implements the ServiceGetter interface from Hubble.
//  - ServiceGetter: https://github.com/cilium/hubble/blob/04ab72591faca62a305ce0715108876167182e04/pkg/parser/getters/getters.go#L52
type LocalServiceGetter struct {
	svc *service.Service
}

// NewLocalServiceGetter returns an initialized pointer to LocalServiceGetter.
func NewLocalServiceGetter(svc *service.Service) *LocalServiceGetter {
	return &LocalServiceGetter{svc: svc}
}

// GetServiceByAddr looks up service by IP/port. Hubble uses this function to annotate flows
// with service information.
func (g *LocalServiceGetter) GetServiceByAddr(ip net.IP, port uint16) (hubbleProto.Service, bool) {
	addr := loadbalancer.L3n4Addr{
		IP: ip,
		L4Addr: loadbalancer.L4Addr{
			Port: port,
		},
	}
	svc, ok := g.svc.GetDeepCopyServiceByAddr(addr)
	if !ok {
		return hubbleProto.Service{}, false
	}
	return hubbleProto.Service{
		Name:      svc.Name,
		Namespace: svc.Namespace,
	}, true
}

// GetServiceByID looks up service by ID.
func (g *LocalServiceGetter) GetServiceByID(id int64) (hubbleProto.Service, bool) {
	svc, ok := g.svc.GetDeepCopyServiceByID(loadbalancer.ServiceID(id))
	if !ok {
		return hubbleProto.Service{}, false
	}
	return hubbleProto.Service{
		Name:      svc.Name,
		Namespace: svc.Namespace,
	}, true
}
