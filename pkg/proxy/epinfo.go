// Copyright 2016-2018 Authors of Cilium
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

package proxy

import (
	"context"
	"net"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
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

func (r *defaultEndpointInfoRegistry) FillEndpointIdentityByID(id identity.NumericIdentity, info *accesslog.EndpointInfo) bool {
	identity := Allocator.LookupIdentityByID(context.TODO(), id)
	if identity == nil {
		return false
	}

	info.Identity = uint64(id)
	info.Labels = identity.Labels.GetModel()
	info.LabelsSHA256 = identity.GetLabelsSHA256()

	return true
}

func (r *defaultEndpointInfoRegistry) FillEndpointIdentityByIP(ip net.IP, info *accesslog.EndpointInfo) bool {
	ep := endpointManager.LookupIP(ip)
	if ep == nil {
		return false
	}

	id, ipv4, ipv6, labels, labelsSHA256, identity, err := ep.GetProxyInfoByFields()
	if err != nil {
		return false
	}

	info.ID = id
	info.IPv4 = ipv4
	info.IPv6 = ipv6
	info.Labels = labels
	info.LabelsSHA256 = labelsSHA256
	info.Identity = identity
	return true
}
