// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"context"
	"net"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"
)

var (
	// DefaultEndpointInfoRegistry is the default instance implementing the
	// EndpointInfoRegistry interface.
	DefaultEndpointInfoRegistry logger.EndpointInfoRegistry = &defaultEndpointInfoRegistry{}
	endpointManager             EndpointLookup
	// Allocator is a package-level variable which is used to lookup security
	// identities from their numeric representation.
	// TODO: plumb an allocator in from callers of these functions vs. having
	// this as a package-level variable.
	Allocator cache.IdentityAllocator
)

// EndpointLookup is any type which maps from IP to the endpoint owning that IP.
type EndpointLookup interface {
	LookupIP(ip net.IP) (ep *endpoint.Endpoint)
}

// defaultEndpointInfoRegistry is the default implementation of the
// EndpointInfoRegistry interface.
type defaultEndpointInfoRegistry struct{}

func (r *defaultEndpointInfoRegistry) FillEndpointInfo(info *accesslog.EndpointInfo, ip net.IP, id identity.NumericIdentity) {
	var ep *endpoint.Endpoint
	if ip != nil {
		if ip.To4() != nil {
			info.IPv4 = ip.String()
		} else {
			info.IPv6 = ip.String()
		}

		// Get (local) endpoint identifier to be reported by cilium monitor
		ep = endpointManager.LookupIP(ip)
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
			ID, exists := ipcache.IPIdentityCache.LookupByIP(ip.String())
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
		info.LabelsSHA256 = identity.GetLabelsSHA256()
	}
}
