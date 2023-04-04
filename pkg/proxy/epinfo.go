// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"context"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	ippkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

var (
	endpointManager EndpointLookup
	// Allocator is a package-level variable which is used to lookup security
	// identities from their numeric representation.
	// TODO: plumb an allocator in from callers of these functions vs. having
	// this as a package-level variable.
	Allocator cache.IdentityAllocator
)

// EndpointLookup is any type which maps from IP to the endpoint owning that IP.
type EndpointLookup interface {
	LookupIP(ip netip.Addr) (ep *endpoint.Endpoint)
}

// endpointInfoRegistry provides a default implementation of the
// logger.EndpointInfoRegistry interface.
type endpointInfoRegistry struct {
	ipcache IPCacheManager
}

func newEndpointInfoRegistry(ipc IPCacheManager) *endpointInfoRegistry {
	return &endpointInfoRegistry{
		ipcache: ipc,
	}
}

func (r *endpointInfoRegistry) FillEndpointInfo(info *accesslog.EndpointInfo, ip net.IP, id identity.NumericIdentity) {
	var ep *endpoint.Endpoint
	if ip != nil {
		if ip.To4() != nil {
			info.IPv4 = ip.String()
		} else {
			info.IPv6 = ip.String()
		}

		// Get (local) endpoint identifier to be reported by cilium monitor
		addr, _ := ippkg.AddrFromIP(ip)
		ep = endpointManager.LookupIP(addr)
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
		} else if ip != nil {
			ID, exists := r.ipcache.LookupByIP(ip.String())
			if exists {
				id = ID.ID
			}
		}
		// Default to WORLD if still unknown
		if id == 0 {
			id = identity.ReservedIdentityWorld
		}
	}
	info.Identity = uint64(id)
	identity := Allocator.LookupIdentityByID(context.TODO(), id)
	if identity != nil {
		info.Labels = identity.Labels.GetModel()
	}
}
