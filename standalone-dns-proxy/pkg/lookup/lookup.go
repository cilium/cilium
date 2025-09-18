// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lookup

import (
	"log/slog"
	"net/netip"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/client"
)

type rulesClient struct {
	Logger            *slog.Logger
	IPtoIdentityTable statedb.RWTable[client.IPtoIdentity]
	DB                *statedb.DB
}

// This is not used by the standalone DNS proxy because it is used by cilium agent to look up DNS rules
// from the in agent dns proxy.
func (r *rulesClient) LookupByIdentity(nid identity.NumericIdentity) []string {
	return []string{}
}

// Note: This is a placeholder for the actual implementation of the ProxyLookupHandler interface.
func (r *rulesClient) LookupRegisteredEndpoint(endpointAddr netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) {
	return nil, false, nil
}

// Note: This is a placeholder for the actual implementation of the ProxyLookupHandler interface.
func (r *rulesClient) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	return ipcache.Identity{}, false
}
