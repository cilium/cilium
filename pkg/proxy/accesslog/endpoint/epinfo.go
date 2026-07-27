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

func NewEndpointInfoRegistry(ipc *ipcache.IPCache, endpointManager endpointmanager.EndpointsLookup, identityAllocator cache.IdentityAllocator) accesslog.EndpointInfoRegistry {
	// **NOTE** The global identity allocator is not yet initialized here;
	// that happens in the daemon init via InitIdentityAllocator().
	// Only the local identity allocator is initialized here.

	return &endpointInfoRegistry{
		ipcache:           ipc,
		endpointManager:   endpointManager,
		identityAllocator: identityAllocator,
	}
}

// FillEndpointInfo fills in as much information as possible from the provided information.
// It will populate empty fields on a best-effort basis.
// Resolving security labels may require accessing the kvstore; labelLookupTimeout sets
// the timeout.
func (r *endpointInfoRegistry) FillEndpointInfo(ctx context.Context, info *accesslog.EndpointInfo, addr netip.Addr) {
	if addr.IsValid() {
		if addr.Is4() {
			info.IPv4 = addr.String()
		} else {
			info.IPv6 = addr.String()
		}
	}

	// Resolve endpoint, if needed and possible.
	// This will fail if the IP does not correspond to an endpoint on this node.
	var ep *endpoint.Endpoint
	if info.ID == 0 {
		ep = r.endpointManager.LookupIP(addr)
		if ep != nil {
			info.ID = ep.GetID()
		}
	}

	// Only resolve the security identity if not passed in, as it may have changed since
	// reported by the proxy. This way we log the security identity and labels used for
	// policy enforcement, if any.
	if info.Identity == 0 {
		// Try and look up identity by endpoint
		if ep != nil {
			secid, err := ep.GetSecurityIdentity()
			// safe to ignore error; just means endpoint is going away.
			// this is best-effort anyways.
			if err == nil && secid != nil {
				info.Identity = uint64(secid.ID)
				info.Labels = secid.LabelArray
			}
		}

		// Fall back to ipcache
		if info.Identity == 0 && addr.IsValid() {
			ID, exists := r.ipcache.LookupByIP(addr.String())
			if exists {
				info.Identity = uint64(ID.ID)
			}
		}

		// Default to WORLD if still unknown
		if info.Identity == 0 {
			info.Identity = uint64(identity.GetWorldIdentityFromIP(addr))
		}
	}

	// Look up security labels if not provided
	if info.Labels == nil {
		// The allocator should already have this in cache, but it may fall back to a
		// remote read if missing. So, provide the context.
		identity := r.identityAllocator.LookupIdentityByID(ctx, identity.NumericIdentity(info.Identity))
		if identity != nil {
			info.Labels = identity.LabelArray
		}
	}
}
