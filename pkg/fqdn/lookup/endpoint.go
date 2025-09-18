// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lookup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node"
)

type ProxyLookupHandler interface {
	// LookupSecIDByIP looks up the security ID for a given IP address
	// from the ipcache.
	LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool)

	// LookupByIdentity is a provided callback that returns the IPs of a given security ID.
	LookupByIdentity(nid identity.NumericIdentity) []string

	// LookupRegisteredEndpoint looks up the endpoint corresponding
	// to a given IP address. It correctly handles *all* IPs belonging to the node, not just that
	// of the node endpoint.
	LookupRegisteredEndpoint(endpointAddr netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error)
}

type proxyLookupHandler struct {
	ipCache         *ipcache.IPCache
	localNodeStore  *node.LocalNodeStore
	endpointManager endpointmanager.EndpointManager
}

var _ ProxyLookupHandler = &proxyLookupHandler{}

func (p *proxyLookupHandler) LookupRegisteredEndpoint(endpointAddr netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) {
	if e := p.endpointManager.LookupIP(endpointAddr); e != nil {
		return e, e.IsHost(), nil
	}

	localNode, err := p.localNodeStore.Get(context.Background())
	if err != nil {
		return nil, true, fmt.Errorf("local node has not been initialized yet: %w", err)
	}

	if localNode.IsNodeIP(endpointAddr) != "" {
		if e := p.endpointManager.GetHostEndpoint(); e != nil {
			return e, true, nil
		} else {
			return nil, true, errors.New("host endpoint has not been created yet")
		}
	}

	return nil, false, fmt.Errorf("cannot find endpoint with IP %s", endpointAddr.String())
}

func (p *proxyLookupHandler) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	return p.ipCache.LookupSecIDByIP(ip)
}

func (p *proxyLookupHandler) LookupByIdentity(nid identity.NumericIdentity) []string {
	return p.ipCache.LookupByIdentity(nid)
}
