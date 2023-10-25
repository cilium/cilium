// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"net/netip"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"
)

// EndpointLookup is any type which maps from IP to the endpoint owning that IP.
type EndpointLookup interface {
	LookupIP(ip netip.Addr) (ep *endpoint.Endpoint)
}

// endpointInfoRegistry provides a default implementation of the logger.EndpointInfoRegistry interface.
type endpointInfoRegistry struct {
	ipcache           *ipcache.IPCache
	endpointManager   EndpointLookup
	identityAllocator cache.IdentityAllocator
}

func NewEndpointInfoRegistry(ipc *ipcache.IPCache, endpointManager endpointmanager.EndpointsLookup, identityAllocator cache.IdentityAllocator) logger.EndpointInfoRegistry {
	// **NOTE** The global identity allocator is not yet initialized here;
	// that happens in the daemon init via InitIdentityAllocator().
	// Only the local identity allocator is initialized here.

	return &endpointInfoRegistry{
		ipcache:           ipc,
		endpointManager:   endpointManager,
		identityAllocator: identityAllocator,
	}
}

func (r *endpointInfoRegistry) FillEndpointInfo(info *accesslog.EndpointInfo, addr netip.Addr, id identity.NumericIdentity) {
	var ep *endpoint.Endpoint
	if addr.IsValid() {
		if addr.Is4() {
			info.IPv4 = addr.String()
		} else {
			info.IPv6 = addr.String()
		}

		// Get (local) endpoint identifier to be reported by cilium monitor
		ep = r.endpointManager.LookupIP(addr)
		if ep != nil {
			info.ID = ep.GetID()
		}
	}

	// Only resolve the security identity if not passed in, as it may have changed since
	// reported by the proxy. This way we log the security identity and labels used for
	// policy enforcement, if any.
	if id == 0 {
		if ep != nil {
			id = ep.GetIdentity()
		} else if addr.IsValid() {
			ID, exists := r.ipcache.LookupByIP(addr.String())
			if exists {
				id = ID.ID
			}
		}
		// Default to WORLD if still unknown
		if id == 0 {
			id = identity.GetWorldIdentityFromIP(addr)
		}
	}
	info.Identity = uint64(id)
	identity := r.identityAllocator.LookupIdentityByID(context.TODO(), id)
	if identity != nil {
		info.Labels = identity.Labels.GetModel()
	}
}
